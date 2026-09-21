package cn.miku.auth.premium;

import cn.miku.auth.config.MikuConfig;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;

/**
 * 正版验证服务：并发查询所有启用的验证源（Mojang / Ashcon / WPME），
 * 任一源确认正版即判定为正版（多源互为镜像，单源故障不影响免密登录）。
 *
 * <p>决策规则（参考 VeloAuth，已获授权使用其代码）：
 * <ol>
 *   <li>Mojang（权威源）返回 PREMIUM → 直接采信；</li>
 *   <li>Mojang 未确认而存在其他源返回 PREMIUM → 采信该源；若此时 Mojang 明确
 *       OFFLINE（数据矛盾）→ 返回 UNKNOWN，由调用方 fail-closed；</li>
 *   <li>Mojang 明确返回 OFFLINE → 直接采信（权威源）；</li>
 *   <li>Mojang 不可用，且所有启用的镜像源都返回 OFFLINE → 采信 OFFLINE（镜像仲裁）；</li>
 *   <li>其余混合情况 → UNKNOWN，由调用方决定是否拒绝登录。</li>
 * </ol>
 *
 * <p>性能与可靠性设计：
 * <ul>
 *   <li>正/负结果分别 TTL 缓存，命中零网络开销；<b>UNKNOWN 不做负缓存</b>，
 *       避免一次网络抖动把某个昵称"锁死"在 fail-closed 拒绝状态；</li>
 *   <li>同昵称并发请求合并为一次外部查询（single-flight）；</li>
 *   <li>三个 API 并发请求，总耗时 ≈ 最快可用源的耗时，任一源确认正版即提前返回；</li>
 *   <li><b>编排不占用线程池</b>：全部用 {@link CompletableFuture} 组合，线程池只跑叶子
 *       网络任务。历史实现曾在编排体内 {@code join()} 自己的子任务，池大小 6 时
 *       6 个并发查询就会把池占满并永久死锁（可被随机昵称连接触发）；</li>
 *   <li>子任务 catch Throwable 后落成 UNKNOWN，单个源的 Error 不会让整次查询悬挂；</li>
 *   <li>整次查询带兜底超时，任何未预期挂起都退化为 UNKNOWN 而不是永久等待；</li>
 *   <li>缓存容量上限，超限时优先清除过期条目。</li>
 * </ul>
 */
public final class PremiumService {

    /** 内存缓存容量上限。 */
    private static final int MAX_CACHE_SIZE = 10_000;
    /** 权威源 ID（Mojang）。 */
    private static final String AUTHORITATIVE = "mojang";

    private final Logger logger;

    /** 启用的验证源；{@link #reload(MikuConfig)} 会整体替换，故为 volatile。 */
    private volatile List<PremiumResolver> resolvers;
    private volatile long hitTtlNanos;
    private volatile long missTtlNanos;
    /** 单次查询的兜底总超时（毫秒）：任一源异常挂起时保证调用方仍能拿到结果。 */
    private volatile int queryTimeoutMillis;

    /** 结果缓存（含过期时间戳）。 */
    private final ConcurrentHashMap<String, CachedResolution> cache = new ConcurrentHashMap<>();
    /** 同昵称请求合并。 */
    private final ConcurrentHashMap<String, CompletableFuture<PremiumResolution>> inFlight = new ConcurrentHashMap<>();
    /** 外部查询线程池：只跑叶子网络任务，不做编排。 */
    private final ExecutorService executor;

    private record CachedResolution(PremiumResolution resolution, long expireAtNanos) {
    }

    public PremiumService(MikuConfig config, Logger logger) {
        this.logger = logger;
        this.resolvers = List.copyOf(buildResolvers(config));
        applyTuning(config);
        this.executor = newExecutor(resolvers.size());
    }

    /**
     * 仅供测试：注入自定义验证源与超时，跳过配置读取。
     */
    PremiumService(Logger logger, List<PremiumResolver> resolvers, int queryTimeoutMillis) {
        this.logger = logger;
        this.resolvers = List.copyOf(resolvers);
        this.hitTtlNanos = 60_000_000_000L;
        this.missTtlNanos = 60_000_000_000L;
        this.queryTimeoutMillis = queryTimeoutMillis;
        this.executor = newExecutor(resolvers.size());
    }

    private static ExecutorService newExecutor(int resolverCount) {
        int threads = Math.max(3, resolverCount * 2);
        return Executors.newFixedThreadPool(threads, runnable -> {
            Thread thread = new Thread(runnable, "MikuAuth-Premium");
            thread.setDaemon(true);
            return thread;
        });
    }

    /** 是否有任何启用的验证源。 */
    public boolean hasResolvers() {
        return !resolvers.isEmpty();
    }

    /**
     * 热重载：按新配置重建验证源与缓存参数。
     * 本实例被 {@code AuthManager} 长期持有，因此必须原地更新而不是替换对象。
     */
    public synchronized void reload(MikuConfig config) {
        this.resolvers = List.copyOf(buildResolvers(config));
        applyTuning(config);
        // 验证源开关可能已变化，旧结果不再可信
        cache.clear();
        if (logger != null) {
            logger.info("[正版验证] 配置已重载：验证源 {} 个，单源超时 {}ms，命中缓存 {}min，未命中缓存 {}min",
                    resolvers.size(), config.premiumTimeoutMillis(),
                    config.premiumHitTtlMinutes(), config.premiumMissTtlMinutes());
        }
    }

    /** 停止服务并释放线程池。 */
    public void shutdown() {
        executor.shutdownNow();
    }

    // ---------------------------------------------------------------------
    // 查询入口
    // ---------------------------------------------------------------------

    /**
     * 异步解析昵称的正版状态。
     * 无任何启用源时直接返回 UNKNOWN，不做网络请求。
     */
    public CompletableFuture<PremiumResolution> resolveAsync(String username) {
        if (!hasResolvers()) {
            return CompletableFuture.completedFuture(
                    PremiumResolution.unknown("service", "未启用验证源"));
        }
        if (!PremiumResolver.isValidUsername(username)) {
            // 不符合 Java 正版昵称规则的名字（Floodgate 前缀、超长昵称等）不可能存在正版账号，
            // 直接判定 OFFLINE；不能返回 UNKNOWN，否则 fail-closed 会把这类合法玩家拒之门外
            return CompletableFuture.completedFuture(
                    PremiumResolution.offline("service", "昵称不符合正版格式"));
        }
        String key = PremiumResolver.cacheKey(username);

        // 1. 缓存命中
        CachedResolution cached = cache.get(key);
        long now = System.nanoTime();
        if (cached != null) {
            if (cached.expireAtNanos() > now) {
                return CompletableFuture.completedFuture(cached.resolution());
            }
            cache.remove(key);
        }

        // 2. 单飞合并并发请求
        CompletableFuture<PremiumResolution> leader = inFlight.get(key);
        if (leader != null) {
            return leader;
        }
        CompletableFuture<PremiumResolution> future = queryApis(username);
        CompletableFuture<PremiumResolution> existing = inFlight.putIfAbsent(key, future);
        if (existing != null) {
            return existing;
        }
        future.whenComplete((result, throwable) -> {
            inFlight.remove(key);
            if (throwable == null && result != null) {
                cacheResult(key, result);
            }
        });
        return future;
    }

    // ---------------------------------------------------------------------
    // 并发查询与汇总
    // ---------------------------------------------------------------------

    /**
     * 并发请求全部验证源并按决策规则汇总。
     *
     * <p><b>本方法绝不阻塞</b>：只负责提交子任务并返回组合后的 future。
     */
    private CompletableFuture<PremiumResolution> queryApis(String username) {
        List<PremiumResolver> active = resolvers;
        if (active.isEmpty()) {
            return CompletableFuture.completedFuture(
                    PremiumResolution.unknown("service", "未启用验证源"));
        }

        ConcurrentHashMap<String, PremiumResolution> results = new ConcurrentHashMap<>(active.size() * 2);
        CompletableFuture<PremiumResolution> firstPremium = new CompletableFuture<>();
        List<CompletableFuture<Void>> tasks = new ArrayList<>(active.size());

        for (PremiumResolver resolver : active) {
            tasks.add(CompletableFuture.runAsync(() -> {
                PremiumResolution resolution;
                try {
                    resolution = resolver.resolve(username);
                } catch (Throwable t) {
                    // 单个源的 Error（类链接失败 / OOM）也必须落成结果，否则汇总永远等不到它
                    resolution = PremiumResolution.unknown(resolver.id(), t.getClass().getSimpleName());
                }
                results.put(resolver.id(), resolution);
                if (resolution.isPremium() && firstPremium.complete(resolution)) {
                    logger.debug("[正版验证] " + username + " 确认为正版（来源: " + resolver.id() + "）");
                }
            }, executor));
        }

        CompletableFuture<PremiumResolution> allDone = CompletableFuture
                .allOf(tasks.toArray(new CompletableFuture<?>[0]))
                .thenApply(ignored -> selectBest(results, username));

        // 任一源确认正版即可提前结束；否则等全部完成做仲裁。最后统一挂兜底超时。
        return allDone.applyToEither(firstPremium, resolution -> resolution)
                .completeOnTimeout(PremiumResolution.unknown("service", "查询超时"),
                        Math.max(1, queryTimeoutMillis), TimeUnit.MILLISECONDS);
    }

    /** 决策规则（见类注释）。 */
    private PremiumResolution selectBest(ConcurrentHashMap<String, PremiumResolution> results, String username) {
        PremiumResolution mojang = results.get(AUTHORITATIVE);
        if (mojang != null && mojang.isPremium()) {
            return mojang;
        }

        // 收集镜像源的 PREMIUM 结果（任一命中即可免密）
        for (PremiumResolution resolution : results.values()) {
            if (resolution.isPremium()) {
                // 权威源明确"不存在"而镜像说"存在"：数据矛盾，交给调用方 fail-closed。
                // 注意：结果里<b>保留镜像给出的 UUID</b> —— 调用方可用它区分
                // "号主已改名的历史映射"（镜像 UUID == 库中该昵称的 UUID）与真正的抢注。
                if (mojang != null && mojang.isOffline()) {
                    logger.warn("[正版验证] " + username + " 各源结果冲突（Mojang=离线，"
                            + resolution.source() + "=正版），拒绝判定");
                    return new PremiumResolution(PremiumResolution.Status.UNKNOWN, resolution.uuid(),
                            resolution.canonicalName(), "service", "各源结果冲突");
                }
                return resolution;
            }
        }

        // Mojang 权威 OFFLINE
        if (mojang != null && mojang.isOffline()) {
            return mojang;
        }
        // 镜像仲裁：所有已启用的镜像源一致 OFFLINE
        List<PremiumResolution> mirrors = new ArrayList<>(results.size());
        for (PremiumResolver resolver : resolvers) {
            if (!resolver.id().equals(AUTHORITATIVE)) {
                PremiumResolution resolution = results.get(resolver.id());
                if (resolution == null || !resolution.isOffline()) {
                    return PremiumResolution.unknown("service", "无法形成判定");
                }
                mirrors.add(resolution);
            }
        }
        if (!mirrors.isEmpty()) {
            return mirrors.get(0);
        }
        return PremiumResolution.unknown("service", "无可用判定");
    }

    // ---------------------------------------------------------------------
    // 缓存
    // ---------------------------------------------------------------------

    private void cacheResult(String key, PremiumResolution resolution) {
        if (resolution.isUnknown()) {
            // 不做负缓存：网络抖动/上游异常导致的 UNKNOWN 若被缓存，
            // fail-closed 下会让该昵称在 TTL 内被持续拒绝
            cache.remove(key);
            return;
        }
        long ttl = resolution.isPremium() ? hitTtlNanos : missTtlNanos;
        if (ttl <= 0) {
            cache.remove(key);
            return;
        }
        if (cache.size() >= MAX_CACHE_SIZE) {
            evictExpired();
        }
        cache.put(key, new CachedResolution(resolution, System.nanoTime() + ttl));
    }

    /** 清理过期缓存条目。 */
    private void evictExpired() {
        long now = System.nanoTime();
        cache.values().removeIf(entry -> entry.expireAtNanos() <= now);
        if (cache.size() >= MAX_CACHE_SIZE) {
            // 仍超限（如 TTL 配置为极长值）时整体清空，缓存仅是性能优化，可安全重建
            cache.clear();
        }
    }

    // ---------------------------------------------------------------------
    // 内部
    // ---------------------------------------------------------------------

    private static List<PremiumResolver> buildResolvers(MikuConfig config) {
        List<PremiumResolver> list = new ArrayList<>(3);
        if (config.premiumEnabled()) {
            if (config.premiumMojangEnabled()) {
                list.add(new PremiumResolver(ResolverConfig.MOJANG, config.premiumTimeoutMillis()));
            }
            if (config.premiumAshconEnabled()) {
                list.add(new PremiumResolver(ResolverConfig.ASHCON, config.premiumTimeoutMillis()));
            }
            if (config.premiumWpmeEnabled()) {
                list.add(new PremiumResolver(ResolverConfig.WPME, config.premiumTimeoutMillis()));
            }
        }
        return list;
    }

    /** 读取超时与缓存相关的可热重载参数。 */
    private void applyTuning(MikuConfig config) {
        this.hitTtlNanos = config.premiumHitTtlMinutes() * 60_000_000_000L;
        this.missTtlNanos = config.premiumMissTtlMinutes() * 60_000_000_000L;
        // 单源超时是 connect/read 各自的超时，一次查询最多经历"连接 + 读取"两段（可能还含一次重试），
        // 这里留足余量：正常路径永远走不到兜底超时，它只为"DNS 挂起"这类病态情况兜底
        this.queryTimeoutMillis = config.premiumTimeoutMillis() * 3 + 1000;
    }
}
