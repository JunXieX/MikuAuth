package cn.miku.auth.security;

import cn.miku.auth.config.MikuConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 跨会话失败计数与临时封禁测试。
 *
 * <p>用可注入的假时钟验证封禁到期，避免测试真的等待若干分钟。
 */
class LoginThrottleTest {

    private static final String IP_A = "10.0.0.1";
    private static final String IP_B = "10.0.0.2";

    @TempDir
    Path tempDir;

    private final AtomicLong now = new AtomicLong(1_700_000_000_000L);
    private LoginThrottle throttle;

    private void load(int maxFailures, int lockoutMinutes) throws Exception {
        Files.writeString(tempDir.resolve("config.yml"), """
                security:
                  max-failures: %d
                  failure-window-minutes: 15
                  lockout-minutes: %d
                """.formatted(maxFailures, lockoutMinutes), StandardCharsets.UTF_8);
        MikuConfig config = new MikuConfig();
        config.load(tempDir, null);
        throttle = new LoginThrottle(config, null, now::get);
    }

    @BeforeEach
    void setUp() throws Exception {
        load(3, 5);
    }

    @Test
    void noLockBeforeThreshold() {
        assertNull(throttle.check(IP_A, "Alice"));
        assertNull(throttle.recordFailure(IP_A, "Alice"));
        assertNull(throttle.recordFailure(IP_A, "Alice"));
        // 阈值是 3，第 3 次才触发
        assertNotNull(throttle.recordFailure(IP_A, "Alice"));
        assertNotNull(throttle.check(IP_A, "Alice"));
    }

    @Test
    void lockAppliesToBothIpAndAccount() {
        for (int i = 0; i < 3; i++) {
            throttle.recordFailure(IP_A, "Alice");
        }
        // 同一 IP 换昵称撞库：被 IP 维度拦住
        assertNotNull(throttle.check(IP_A, "Bob"));
        // 同一账号换 IP：被账号维度拦住
        assertNotNull(throttle.check(IP_B, "Alice"));
        // 无关的 IP + 昵称不受影响
        assertNull(throttle.check(IP_B, "Bob"));
    }

    @Test
    void lockExpiresAfterConfiguredMinutes() {
        for (int i = 0; i < 3; i++) {
            throttle.recordFailure(IP_A, "Alice");
        }
        assertNotNull(throttle.check(IP_A, "Alice"));

        now.addAndGet(4 * 60_000L);
        assertNotNull(throttle.check(IP_A, "Alice"), "封禁期内仍应拒绝");

        now.addAndGet(61_000L);
        assertNull(throttle.check(IP_A, "Alice"), "封禁到期后应放行");
    }

    @Test
    void successfulLoginResetsCounters() {
        throttle.recordFailure(IP_A, "Alice");
        throttle.recordFailure(IP_A, "Alice");
        throttle.reset(IP_A, "Alice");

        // 计数已清零，再失败两次仍不应触发（阈值 3）
        assertNull(throttle.recordFailure(IP_A, "Alice"));
        assertNull(throttle.recordFailure(IP_A, "Alice"));
        assertNotNull(throttle.recordFailure(IP_A, "Alice"));
    }

    @Test
    void adminUnlockClearsByNameAndByIp() {
        for (int i = 0; i < 3; i++) {
            throttle.recordFailure(IP_A, "Alice");
        }
        assertTrue(throttle.unlock("Alice"), "按账号名解锁应命中");
        assertNull(throttle.check(IP_B, "Alice"), "账号维度已解锁");
        assertNotNull(throttle.check(IP_A, "Bob"), "IP 维度仍在封禁中");

        assertTrue(throttle.unlock(IP_A), "按 IP 解锁应命中");
        assertNull(throttle.check(IP_A, "Bob"));
        assertFalse(throttle.unlock(IP_A), "重复解锁应返回未命中");
    }

    @Test
    void purgeDropsStaleCounters() {
        throttle.recordFailure(IP_A, "Alice");
        throttle.purge();
        // 窗口内不应被清理：计数仍然有效
        assertNull(throttle.recordFailure(IP_A, "Alice"));
        assertNotNull(throttle.recordFailure(IP_A, "Alice"));

        // 远超过窗口 + 封禁时长后，记录被清理
        now.addAndGet(2 * 60 * 60_000L);
        throttle.purge();
        assertNull(throttle.check(IP_A, "Alice"));
    }

    @Test
    void thresholdZeroDisablesProtection() throws Exception {
        load(0, 5);
        assertFalse(throttle.enabled());
        for (int i = 0; i < 10; i++) {
            assertNull(throttle.recordFailure(IP_A, "Alice"));
        }
        assertNull(throttle.check(IP_A, "Alice"));
    }
}
