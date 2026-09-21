package cn.miku.auth.premium;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 正版验证服务的决策规则与并发行为测试。
 *
 * <p>重点回归：历史实现把"编排任务"提交到与子任务相同的固定线程池，并在编排体内
 * {@code join()} 自己的子任务——池大小 6 时只要同时有 6 个缓存未命中的查询，
 * 线程就会被编排任务占满、子任务永远排不到线程，整台代理的新玩家登录全部挂死。
 * {@link #concurrentLookupsDoNotDeadlock()} 就是这条缺陷的回归用例。
 */
class PremiumServiceTest {

    /** 可编程的验证源：延迟指定毫秒后返回预设结果，或抛出指定 Error。 */
    private static final class FakeResolver extends PremiumResolver {
        private final PremiumResolution result;
        private final long delayMillis;
        private final Error failure;
        private final AtomicInteger calls = new AtomicInteger();

        FakeResolver(ResolverConfig config, PremiumResolution result, long delayMillis, Error failure) {
            super(config, 1000);
            this.result = result;
            this.delayMillis = delayMillis;
            this.failure = failure;
        }

        @Override
        PremiumResolution resolve(String username) {
            calls.incrementAndGet();
            if (delayMillis > 0) {
                try {
                    Thread.sleep(delayMillis);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            if (failure != null) {
                throw failure;
            }
            return result;
        }
    }

    private static PremiumResolver offline(ResolverConfig config, long delay) {
        return new FakeResolver(config, PremiumResolution.offline(config.id(), "test"), delay, null);
    }

    private static PremiumResolver unknown(ResolverConfig config, long delay) {
        return new FakeResolver(config, PremiumResolution.unknown(config.id(), "test"), delay, null);
    }

    private static PremiumResolution await(PremiumService service, String username) throws Exception {
        return service.resolveAsync(username).get(5, TimeUnit.SECONDS);
    }

    // ---------------------------------------------------------------------
    // 并发行为
    // ---------------------------------------------------------------------

    @Test
    void concurrentLookupsDoNotDeadlock() throws Exception {
        List<PremiumResolver> resolvers = List.of(
                offline(ResolverConfig.MOJANG, 60),
                offline(ResolverConfig.ASHCON, 60),
                offline(ResolverConfig.WPME, 60));
        PremiumService service = new PremiumService(null, resolvers, 5000);
        try {
            // 12 个并发查询 × 3 个子任务；旧实现在 6 个并发时就会永久死锁
            List<CompletableFuture<PremiumResolution>> futures = new ArrayList<>();
            for (int i = 0; i < 12; i++) {
                futures.add(service.resolveAsync("user" + i));
            }
            for (CompletableFuture<PremiumResolution> future : futures) {
                assertTrue(future.get(5, TimeUnit.SECONDS).isOffline());
            }
        } finally {
            service.shutdown();
        }
    }

    @Test
    void resolverThrowingErrorStillCompletes() throws Exception {
        List<PremiumResolver> resolvers = List.of(
                new FakeResolver(ResolverConfig.MOJANG, null, 10, new NoClassDefFoundError("boom")));
        PremiumService service = new PremiumService(null, resolvers, 5000);
        try {
            // 子任务抛 Error 时若不做兜底，汇总会永远等不到结果
            assertTrue(await(service, "user1").isUnknown());
        } finally {
            service.shutdown();
        }
    }

    // ---------------------------------------------------------------------
    // 决策规则
    // ---------------------------------------------------------------------

    @Test
    void mojangPremiumWins() throws Exception {
        UUID uuid = UUID.randomUUID();
        List<PremiumResolver> resolvers = List.of(
                new FakeResolver(ResolverConfig.MOJANG,
                        PremiumResolution.premium(uuid, "user1", "mojang"), 10, null),
                offline(ResolverConfig.ASHCON, 10),
                offline(ResolverConfig.WPME, 10));
        PremiumService service = new PremiumService(null, resolvers, 5000);
        try {
            PremiumResolution result = await(service, "user1");
            assertTrue(result.isPremium());
            assertEquals("mojang", result.source());
            assertEquals(uuid, result.uuid());
        } finally {
            service.shutdown();
        }
    }

    @Test
    void firstPremiumResultReturnsEarly() throws Exception {
        List<PremiumResolver> resolvers = List.of(
                new FakeResolver(ResolverConfig.MOJANG,
                        PremiumResolution.premium(UUID.randomUUID(), "user1", "mojang"), 10, null),
                offline(ResolverConfig.ASHCON, 2000),
                offline(ResolverConfig.WPME, 2000));
        PremiumService service = new PremiumService(null, resolvers, 8000);
        try {
            long startedAt = System.nanoTime();
            assertTrue(await(service, "user1").isPremium());
            long elapsedMillis = (System.nanoTime() - startedAt) / 1_000_000L;
            // 权威源已确认正版，不应等待两个慢镜像
            assertTrue(elapsedMillis < 1500, "提前返回失效，耗时 " + elapsedMillis + "ms");
        } finally {
            service.shutdown();
        }
    }

    @Test
    void allSourcesOfflineGivesOffline() throws Exception {
        List<PremiumResolver> resolvers = List.of(
                offline(ResolverConfig.MOJANG, 5),
                offline(ResolverConfig.ASHCON, 5),
                offline(ResolverConfig.WPME, 5));
        PremiumService service = new PremiumService(null, resolvers, 5000);
        try {
            assertTrue(await(service, "user1").isOffline());
        } finally {
            service.shutdown();
        }
    }

    @Test
    void mojangUnavailableWithMirrorsOfflineGivesOffline() throws Exception {
        List<PremiumResolver> resolvers = List.of(
                unknown(ResolverConfig.MOJANG, 5),
                offline(ResolverConfig.ASHCON, 5),
                offline(ResolverConfig.WPME, 5));
        PremiumService service = new PremiumService(null, resolvers, 5000);
        try {
            // 镜像仲裁：Mojang 不可用，但所有镜像一致判定离线
            assertTrue(await(service, "user1").isOffline());
        } finally {
            service.shutdown();
        }
    }

    @Test
    void mixedUnknownResultsGiveUnknown() throws Exception {
        List<PremiumResolver> resolvers = List.of(
                unknown(ResolverConfig.MOJANG, 5),
                offline(ResolverConfig.ASHCON, 5),
                unknown(ResolverConfig.WPME, 5));
        PremiumService service = new PremiumService(null, resolvers, 5000);
        try {
            assertTrue(await(service, "user1").isUnknown());
        } finally {
            service.shutdown();
        }
    }

    // ---------------------------------------------------------------------
    // 缓存与昵称校验
    // ---------------------------------------------------------------------

    @Test
    void unknownResultsAreNotCached() throws Exception {
        FakeResolver mojang = new FakeResolver(ResolverConfig.MOJANG,
                PremiumResolution.unknown("mojang", "网络故障"), 0, null);
        PremiumService service = new PremiumService(null, List.of(mojang), 5000);
        try {
            assertTrue(await(service, "user1").isUnknown());
            assertTrue(await(service, "user1").isUnknown());
            // UNKNOWN 若被负缓存，fail-closed 下会让该昵称在 TTL 内被持续拒绝
            assertEquals(2, mojang.calls.get());
        } finally {
            service.shutdown();
        }
    }

    @Test
    void offlineResultsAreCached() throws Exception {
        FakeResolver mojang = new FakeResolver(ResolverConfig.MOJANG,
                PremiumResolution.offline("mojang", "不存在"), 0, null);
        PremiumService service = new PremiumService(null, List.of(mojang), 5000);
        try {
            assertTrue(await(service, "user1").isOffline());
            assertTrue(await(service, "user1").isOffline());
            assertEquals(1, mojang.calls.get());
        } finally {
            service.shutdown();
        }
    }

    @Test
    void nonJavaNicknameIsTreatedAsOffline() throws Exception {
        FakeResolver mojang = new FakeResolver(ResolverConfig.MOJANG,
                PremiumResolution.premium(UUID.randomUUID(), "x", "mojang"), 0, null);
        PremiumService service = new PremiumService(null, List.of(mojang), 5000);
        try {
            // 基岩版前缀（含 '.'）与超短昵称都不可能是 Java 正版账号：
            // 必须判离线，否则 fail-closed 会把这类合法玩家直接拒之门外
            assertTrue(service.resolveAsync(".Bedrock").get(5, TimeUnit.SECONDS).isOffline());
            assertTrue(service.resolveAsync("ab").get(5, TimeUnit.SECONDS).isOffline());
            assertEquals(0, mojang.calls.get());
        } finally {
            service.shutdown();
        }
    }
}
