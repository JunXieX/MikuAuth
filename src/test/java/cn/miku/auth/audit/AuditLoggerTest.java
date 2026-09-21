package cn.miku.auth.audit;

import cn.miku.auth.config.MikuConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * 审计记录器的测试。
 *
 * <p>重点验证"失败事件合并"这一取舍：暴破时同一账号+IP 的重复失败只落一条，
 * 而成功事件与不同来源的失败必须照常记录——否则审计就会丢失关键线索。
 */
class AuditLoggerTest {

    @TempDir
    Path dataDirectory;

    private FakeAuditRepository repository;
    private AuditLogger logger;

    @BeforeEach
    void setUp() throws IOException {
        MikuConfig config = loadConfig();
        repository = new FakeAuditRepository();
        logger = new AuditLogger(repository, config, org.slf4j.helpers.NOPLogger.NOP_LOGGER);
    }

    @Test
    void mergesRepeatedFailuresFromSameAccountAndIp() {
        for (int i = 0; i < 5; i++) {
            logger.record(AuditAction.LOGIN_FAIL, "alice", null, "1.2.3.4", "密码错误（第 " + (i + 1) + " 次）");
        }

        assertEquals(1, repository.entries.size(),
                "同一账号+IP 在合并窗口内只应落一条，避免暴破刷爆审计表");
    }

    @Test
    void recordsFailuresFromDifferentIpsSeparately() {
        logger.record(AuditAction.LOGIN_FAIL, "alice", null, "1.2.3.4", "密码错误");
        logger.record(AuditAction.LOGIN_FAIL, "alice", null, "5.6.7.8", "密码错误");

        assertEquals(2, repository.entries.size(), "不同来源 IP 的失败必须分别记录（可能是撞库）");
    }

    @Test
    void mergesRepeatedIpLimitRejections() {
        // 注册被 IP 配额拦下时玩家可以反复提交 /register，同样需要合并
        for (int i = 0; i < 5; i++) {
            logger.record(AuditAction.REJECT_IP_LIMIT, "alice", null, "1.2.3.4", "达到 IP 账号上限");
        }

        assertEquals(1, repository.entries.size(), "同一账号+IP 的 IP 超限拒绝只应落一条");
    }

    @Test
    void neverMergesSuccessEvents() {
        logger.record(AuditAction.LOGIN_SUCCESS, "alice", null, "1.2.3.4", "密码登录");
        logger.record(AuditAction.LOGIN_SUCCESS, "alice", null, "1.2.3.4", "密码登录");
        logger.record(AuditAction.LOGIN_SESSION, "alice", null, "1.2.3.4", "同 IP 会话免密");

        assertEquals(3, repository.entries.size(), "成功类事件每次都应有独立记录");
    }

    @Test
    void disabledAuditWritesNothing() throws IOException {
        Files.writeString(dataDirectory.resolve("config.yml"), """
                server:
                  auth-server: "auth"
                audit:
                  enabled: false
                """, StandardCharsets.UTF_8);
        MikuConfig config = new MikuConfig();
        config.load(dataDirectory, null);
        AuditLogger disabled = new AuditLogger(repository, config,
                org.slf4j.helpers.NOPLogger.NOP_LOGGER);

        disabled.record(AuditAction.LOGIN_SUCCESS, "alice", null, "1.2.3.4", "密码登录");

        assertEquals(0, repository.entries.size());
    }

    private MikuConfig loadConfig() throws IOException {
        Files.writeString(dataDirectory.resolve("config.yml"), """
                server:
                  auth-server: "auth"
                audit:
                  enabled: true
                """, StandardCharsets.UTF_8);
        MikuConfig config = new MikuConfig();
        config.load(dataDirectory, null);
        return config;
    }

    private static final class FakeAuditRepository implements AuditRepository {

        private final List<AuditEntry> entries = new CopyOnWriteArrayList<>();

        @Override
        public CompletableFuture<Void> appendAudit(AuditEntry entry) {
            entries.add(entry);
            return CompletableFuture.completedFuture(null);
        }

        @Override
        public CompletableFuture<List<AuditEntry>> findAuditByNickname(String nickname, int limit) {
            return CompletableFuture.completedFuture(List.copyOf(entries));
        }

        @Override
        public CompletableFuture<List<AuditEntry>> findAuditByIp(String ip, int limit) {
            return CompletableFuture.completedFuture(List.copyOf(entries));
        }

        @Override
        public CompletableFuture<Integer> purgeExpiredAudit(long beforeMillis) {
            return CompletableFuture.completedFuture(0);
        }
    }
}
