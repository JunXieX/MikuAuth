package cn.miku.auth.auth;

import cn.miku.auth.config.MikuConfig;
import cn.miku.auth.config.MikuMessages;
import cn.miku.auth.premium.PremiumResolution;
import cn.miku.auth.premium.PremiumService;
import net.kyori.adventure.text.Component;
import org.slf4j.Logger;

import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 正版判定器：负责"这个昵称是不是正版"以及"这条连接的正版身份是否已被核实"。
 *
 * <p>从 {@link AuthManager} 抽出，因为它承载的是<b>一套自洽的缓存协议</b>，而不是认证流程本身：
 * <ol>
 *   <li>PreLogin 阶段查询三源，确认为正版后登记<b>期望 UUID</b>；</li>
 *   <li>GameProfileRequest 阶段拿实际 UUID 与期望比对（不匹配即抢注，拒绝连接），
 *       通过后标记该连接"已核实"，供认证阶段免密；</li>
 *   <li>两张缓存都带时间戳，超时未消费即清理（客户端取消、连接中断等残留）。</li>
 * </ol>
 *
 * <p>把这段协议独立出来，好处是 {@link AuthManager} 不必再关心"缓存何时清理、
 * 抢注如何判定"，而判定器本身也不依赖数据库——改名迁移、死昵称清理等需要查库的
 * 业务编排仍留在状态机里。
 */
public final class PremiumDecider {

    /** 缓存条目保留时长：超过该时长仍未消费即视为残留（客户端取消连接等）。 */
    private static final long STALE_MILLIS = 60_000L;
    /** 清理触发的阈值：小规模时不必遍历。 */
    private static final int PURGE_THRESHOLD = 32;

    private final PremiumService premiumService;
    private final MikuConfig config;
    private final MikuMessages messages;
    private final Logger logger;

    /** 昵称（归一化）→ 期望的正版 UUID，GameProfileRequest 阶段校验用。 */
    private final ConcurrentHashMap<String, Expectation> expectations = new ConcurrentHashMap<>();
    /** 已通过正版会话校验的连接 UUID → 校验时间（免密判定依据）。 */
    private final ConcurrentHashMap<UUID, Long> verifiedUuids = new ConcurrentHashMap<>();

    public PremiumDecider(PremiumService premiumService, MikuConfig config,
                          MikuMessages messages, Logger logger) {
        this.premiumService = premiumService;
        this.config = config;
        this.messages = messages;
        this.logger = logger;
    }

    private record Expectation(UUID uuid, long createdAt) {
    }

    // ---------------------------------------------------------------------
    // 查询
    // ---------------------------------------------------------------------

    /** 是否配置了可用的正版验证源（未配置时调用方应直接按离线处理，避免无谓查询）。 */
    public boolean hasResolvers() {
        return premiumService.hasResolvers();
    }

    /** 正版验证是否启用（配置开关 + 验证源可用）。 */
    public boolean available() {
        return config.premiumEnabled() && hasResolvers();
    }

    /**
     * 并发查询三源并归并结果。
     *
     * <p>仅在 {@link #available()} 为真时有意义；调用方需自行处理"未启用"的情形。
     * 查询失败由 {@link PremiumResolution} 表达（{@code allFailed}），不抛异常。
     */
    public CompletableFuture<PremiumResolution> resolveAsync(String username) {
        return premiumService.resolveAsync(username);
    }

    // ---------------------------------------------------------------------
    // 期望 UUID 的登记与校验
    // ---------------------------------------------------------------------

    /** 登记期望 UUID（PreLogin 判定为正版后调用）。 */
    public void expect(String username, UUID mojangUuid) {
        if (mojangUuid == null) {
            return;
        }
        expectations.put(MikuConfig.normalize(username),
                new Expectation(mojangUuid, System.currentTimeMillis()));
    }

    /**
     * 校验正版连接的实际 UUID 是否与期望一致。
     *
     * <p>注意：本方法在 {@code GameProfileRequestEvent}（事件线程）中被调用，
     * 只做内存比对，不含任何 IO。
     *
     * @return null = 通过（或本连接不涉及正版判定）；否则为拒绝原因（抢注攻击）
     */
    public Component verifyProfile(String username, UUID actualUuid) {
        String key = MikuConfig.normalize(username);
        Expectation expectation = expectations.get(key);
        if (expectation == null) {
            return null; // 非 PREMIUM 决策连接，交给密码/注册流程
        }
        if (expectation.uuid().equals(actualUuid)) {
            // 正版会话校验通过：标记连接已验证（免密依据），期望记录同步消费
            verifiedUuids.put(actualUuid, System.currentTimeMillis());
            expectations.remove(key);
            return null;
        }
        // 期望 UUID 不匹配：抢注攻击
        expectations.remove(key);
        logger.warn("[安全] {} 正版 UUID 不匹配（期望 {}，实际 {}），拒绝连接",
                username, expectation.uuid(), actualUuid);
        return messages.component("kick.name-snipe");
    }

    /** 该连接是否已通过正版会话校验（免密判定依据）。 */
    public boolean isVerified(UUID playerUuid) {
        return verifiedUuids.containsKey(playerUuid);
    }

    /**
     * 撤销某连接的"已验证"标记（自愈路径用）。
     *
     * <p>场景：玩家位于认证服却没有认证会话（状态残留），需要重新走一遍流程——
     * 若不清除该标记，认证入口会静默短路，玩家永远进不了注册/登录。
     */
    public void revokeVerified(UUID playerUuid) {
        verifiedUuids.remove(playerUuid);
    }

    /** 丢弃某昵称的期望记录（管理员清除了正版绑定后，让旧决策立即失效）。 */
    public void forgetExpectation(String username) {
        expectations.remove(MikuConfig.normalize(username));
    }

    // ---------------------------------------------------------------------
    // 清理
    // ---------------------------------------------------------------------

    /** 玩家断线：清理两张表中与该连接相关的残留。 */
    public void forget(UUID playerUuid, String username) {
        verifiedUuids.remove(playerUuid);
        expectations.remove(MikuConfig.normalize(username));
    }

    /** 清理超过 {@link #STALE_MILLIS} 未消费的条目。 */
    public void purgeStale() {
        if (expectations.size() < PURGE_THRESHOLD && verifiedUuids.size() < PURGE_THRESHOLD) {
            return;
        }
        long cutoff = System.currentTimeMillis() - STALE_MILLIS;
        expectations.values().removeIf(expectation -> expectation.createdAt() < cutoff);
        verifiedUuids.values().removeIf(verifiedAt -> verifiedAt < cutoff);
    }
}
