package cn.miku.auth.database;

import cn.miku.auth.audit.AuditAction;
import cn.miku.auth.audit.AuditEntry;
import cn.miku.auth.config.MikuConfig;
import cn.miku.auth.util.UuidUtil;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 数据层行为测试：注册结果语义、IP 配额口径、正版绑定清除与会话生命周期。
 */
class DatabaseManagerTest {

    @TempDir
    Path tempDir;

    private DatabaseManager database;

    @BeforeEach
    void setUp() throws Exception {
        MikuConfig config = new MikuConfig();
        config.load(tempDir, null);
        database = new DatabaseManager(tempDir, config, LoggerFactory.getLogger("MikuAuthTest"));
    }

    @AfterEach
    void tearDown() {
        if (database != null) {
            database.close();
        }
    }

    @Test
    void registerThenFind() throws Exception {
        assertEquals(DatabaseManager.RegisterResult.OK,
                database.register(UUID.randomUUID(), "Alice", "hash", StoredPlayer.TYPE_OFFLINE, "10.0.0.1")
                        .get(5, TimeUnit.SECONDS));

        Optional<StoredPlayer> found = database.findPlayer("alice").get(5, TimeUnit.SECONDS);
        assertTrue(found.isPresent());
        assertEquals("Alice", found.get().nickname());
        assertTrue(found.get().hasPassword());
        assertFalse(found.get().isPremiumType());
    }

    @Test
    void duplicateRegistrationIsReportedAsDuplicate() throws Exception {
        database.register(UUID.randomUUID(), "Alice", "hash", StoredPlayer.TYPE_OFFLINE, "10.0.0.1")
                .get(5, TimeUnit.SECONDS);
        // 昵称冲突必须与"数据库故障"区分开，否则玩家会看到误导性的错误提示
        assertEquals(DatabaseManager.RegisterResult.DUPLICATE,
                database.register(UUID.randomUUID(), "Alice", "hash2", StoredPlayer.TYPE_OFFLINE, "10.0.0.1")
                        .get(5, TimeUnit.SECONDS));
    }

    @Test
    void premiumAccountsDoNotConsumeIpQuota() throws Exception {
        database.register(UUID.randomUUID(), "Offline1", "hash", StoredPlayer.TYPE_OFFLINE, "10.0.0.1")
                .get(5, TimeUnit.SECONDS);
        database.register(UUID.randomUUID(), "Offline2", "hash", StoredPlayer.TYPE_OFFLINE, "10.0.0.1")
                .get(5, TimeUnit.SECONDS);
        database.register(UUID.randomUUID(), "Premium1", null, StoredPlayer.TYPE_PREMIUM, "10.0.0.1")
                .get(5, TimeUnit.SECONDS);
        database.register(UUID.randomUUID(), "Premium2", null, StoredPlayer.TYPE_PREMIUM, "10.0.0.1")
                .get(5, TimeUnit.SECONDS);

        // 正版账号由正版玩家自动登记，不计入配额；否则同 IP 下 3 个正版玩家会堵死离线注册
        assertEquals(2, database.countAccountsByIp("10.0.0.1").get(5, TimeUnit.SECONDS));
    }

    @Test
    void loginFromAnotherIpCountsTowardsThatIp() throws Exception {
        database.register(UUID.randomUUID(), "Alice", "hash", StoredPlayer.TYPE_OFFLINE, "10.0.0.1")
                .get(5, TimeUnit.SECONDS);
        database.finishLogin("Alice", "10.0.0.2", 0L).get(5, TimeUnit.SECONDS);

        assertEquals(1, database.countAccountsByIp("10.0.0.2").get(5, TimeUnit.SECONDS));
        List<StoredPlayer> accounts = database.findAccountsByIp("10.0.0.2").get(5, TimeUnit.SECONDS);
        assertEquals(1, accounts.size());
        assertEquals("Alice", accounts.get(0).nickname());
    }

    @Test
    void clearPremiumBindingDowngradesAccount() throws Exception {
        UUID premiumUuid = UUID.randomUUID();
        database.register(premiumUuid, "Renamed", null, StoredPlayer.TYPE_PREMIUM, "10.0.0.1")
                .get(5, TimeUnit.SECONDS);

        assertTrue(database.clearPremiumBinding("renamed").get(5, TimeUnit.SECONDS));
        StoredPlayer after = database.findPlayer("Renamed").get(5, TimeUnit.SECONDS).orElseThrow();
        assertFalse(after.isPremiumType());
        assertEquals(null, after.premiumUuid());
        // 重复清除应返回 false（本来就没有绑定了）
        assertFalse(database.clearPremiumBinding("Renamed").get(5, TimeUnit.SECONDS));
    }

    @Test
    void deletePasswordKeepsAccount() throws Exception {
        database.register(UUID.randomUUID(), "Alice", "hash", StoredPlayer.TYPE_OFFLINE, "10.0.0.1")
                .get(5, TimeUnit.SECONDS);
        assertTrue(database.deletePassword("Alice").get(5, TimeUnit.SECONDS));

        StoredPlayer after = database.findPlayer("Alice").get(5, TimeUnit.SECONDS).orElseThrow();
        assertFalse(after.hasPassword());
    }

    @Test
    void findPlayerByUuidReturnsAccount() throws Exception {
        UUID uuid = UUID.randomUUID();
        database.register(uuid, "Alice", "hash", StoredPlayer.TYPE_OFFLINE, "10.0.0.1")
                .get(5, TimeUnit.SECONDS);

        assertEquals("Alice", database.findPlayerByUuid(uuid).get(5, TimeUnit.SECONDS)
                .orElseThrow().nickname());
        assertTrue(database.findPlayerByUuid(UUID.randomUUID()).get(5, TimeUnit.SECONDS).isEmpty());
    }

    @Test
    void renameAccountKeepsDataAndReleasesOldNickname() throws Exception {
        UUID uuid = UUID.randomUUID();
        database.register(uuid, "Alice", "hash", StoredPlayer.TYPE_PREMIUM, "10.0.0.1")
                .get(5, TimeUnit.SECONDS);

        assertTrue(database.renameAccount(uuid, "Bob").get(5, TimeUnit.SECONDS));

        // 数据跟着 UUID 走：密码与注册信息保留，昵称已更新
        StoredPlayer renamed = database.findPlayerByUuid(uuid).get(5, TimeUnit.SECONDS).orElseThrow();
        assertEquals("Bob", renamed.nickname());
        assertEquals("bob", renamed.nicknameLower());
        assertEquals("hash", renamed.passwordHash());
        // 旧昵称被释放，可被新玩家使用
        assertTrue(database.findPlayer("Alice").get(5, TimeUnit.SECONDS).isEmpty());
        assertEquals(DatabaseManager.RegisterResult.OK,
                database.register(UUID.randomUUID(), "Alice", "hash2", StoredPlayer.TYPE_OFFLINE, "10.0.0.2")
                        .get(5, TimeUnit.SECONDS));
    }

    @Test
    void renameAccountFailsWhenTargetNicknameTaken() throws Exception {
        UUID uuid = UUID.randomUUID();
        database.register(uuid, "Alice", "hash", StoredPlayer.TYPE_PREMIUM, "10.0.0.1")
                .get(5, TimeUnit.SECONDS);
        database.register(UUID.randomUUID(), "Bob", "hash2", StoredPlayer.TYPE_OFFLINE, "10.0.0.2")
                .get(5, TimeUnit.SECONDS);

        // 新昵称已被占用 → 迁移失败但不抛异常，原记录保持不动
        assertFalse(database.renameAccount(uuid, "Bob").get(5, TimeUnit.SECONDS));
        assertEquals("Alice", database.findPlayerByUuid(uuid).get(5, TimeUnit.SECONDS)
                .orElseThrow().nickname());
    }

    @Test
    void releaseStaleAccountDeletesOnlyPasswordlessPremiumRecords() throws Exception {
        UUID historical = UUID.randomUUID();
        database.register(historical, "OldName", null, StoredPlayer.TYPE_PREMIUM, "10.0.0.1")
                .get(5, TimeUnit.SECONDS);
        // 带密码的正版记录（管理员 setpassword 产生）不应被自动清理
        UUID withPassword = UUID.randomUUID();
        database.register(withPassword, "KeepMe", "hash", StoredPlayer.TYPE_PREMIUM, "10.0.0.1")
                .get(5, TimeUnit.SECONDS);
        // 离线账号同样不受影响
        database.register(UUID.randomUUID(), "Offline", "hash", StoredPlayer.TYPE_OFFLINE, "10.0.0.1")
                .get(5, TimeUnit.SECONDS);

        // UUID 不匹配（镜像给的是另一个 UUID）→ 不清理，避免误删
        assertFalse(database.releaseStaleAccount("OldName", UUID.randomUUID()).get(5, TimeUnit.SECONDS));
        // UUID 匹配 → 清理并释放昵称
        assertTrue(database.releaseStaleAccount("OldName", historical).get(5, TimeUnit.SECONDS));
        assertTrue(database.findPlayer("OldName").get(5, TimeUnit.SECONDS).isEmpty());

        // 带密码的正版记录：即便 UUID 匹配也不清理
        assertFalse(database.releaseStaleAccount("KeepMe", withPassword).get(5, TimeUnit.SECONDS));
        assertTrue(database.findPlayer("KeepMe").get(5, TimeUnit.SECONDS).isPresent());
        // 离线账号：不会被清理
        assertFalse(database.releaseStaleAccount("Offline", null).get(5, TimeUnit.SECONDS));
    }

    @Test
    void clearPremiumBindingSwitchesIdentityToOfflineUuid() throws Exception {
        UUID premiumUuid = UUID.randomUUID();
        database.register(premiumUuid, "Alice", "hash", StoredPlayer.TYPE_PREMIUM, "10.0.0.1")
                .get(5, TimeUnit.SECONDS);

        assertTrue(database.clearPremiumBinding("Alice").get(5, TimeUnit.SECONDS));

        // 解绑后身份键必须换成离线 UUID，否则玩家离线登录时会对不上账号
        StoredPlayer after = database.findPlayer("Alice").get(5, TimeUnit.SECONDS).orElseThrow();
        assertEquals(UuidUtil.offlineUuid("Alice"), after.uuid());
        assertFalse(after.isPremiumType());
        assertTrue(database.findPlayerByUuid(premiumUuid).get(5, TimeUnit.SECONDS).isEmpty());
    }

    @Test
    void sessionLifecycle() throws Exception {
        long expiresAt = System.currentTimeMillis() + 60_000L;
        database.saveSession("Alice", "10.0.0.1", expiresAt).get(5, TimeUnit.SECONDS);

        DatabaseManager.Session session = database.findSession("alice").get(5, TimeUnit.SECONDS).orElseThrow();
        assertEquals("10.0.0.1", session.ip());

        // 二次写入走 upsert（同一主键刷新，而不是报主键冲突）
        long refreshed = expiresAt + 60_000L;
        database.saveSession("Alice", "10.0.0.2", refreshed).get(5, TimeUnit.SECONDS);
        DatabaseManager.Session updated = database.findSession("Alice").get(5, TimeUnit.SECONDS).orElseThrow();
        assertEquals("10.0.0.2", updated.ip());
        assertEquals(refreshed, updated.expiresAt());

        // 过期会话不返回，且能被清理
        database.saveSession("Bob", "10.0.0.3", System.currentTimeMillis() - 1000L).get(5, TimeUnit.SECONDS);
        assertTrue(database.findSession("Bob").get(5, TimeUnit.SECONDS).isEmpty());
        assertEquals(1, database.purgeExpiredSessions().get(5, TimeUnit.SECONDS));

        // 清除会话（改密/重置时调用）
        database.clearSession("Alice").get(5, TimeUnit.SECONDS);
        assertTrue(database.findSession("Alice").get(5, TimeUnit.SECONDS).isEmpty());
    }

    // ---------------------------------------------------------------------
    // 审计事件解析
    // ---------------------------------------------------------------------

    /**
     * 无法识别的 action（降级运行读到新版本写入的值）必须映射为 {@link AuditAction#UNKNOWN}。
     *
     * <p>回归点：解析失败曾回退成 {@code ADMIN_ACTION}，而枚举注释与
     * {@code /mikuauth audit} 的展示都要求这种情况显示为「未知事件」——
     * 伪装成"管理员操作"会把排障方向带偏（该枚举因此成了永不出现的死值）。
     */
    @Test
    void unknownAuditActionIsReportedAsUnknownNotAdminAction() throws Exception {
        long now = System.currentTimeMillis();
        try (Connection connection = DriverManager.getConnection(
                "jdbc:sqlite:" + tempDir.resolve("database.db").toAbsolutePath());
             PreparedStatement ps = connection.prepareStatement("""
                     INSERT INTO miku_audit_log
                         (nickname, nickname_lower, uuid, ip, action, detail, created_at)
                     VALUES (?, ?, ?, ?, ?, ?, ?)""")) {
            ps.setString(1, "Alice");
            ps.setString(2, "alice");
            ps.setString(3, null);
            ps.setString(4, "10.0.0.1");
            ps.setString(5, "FUTURE_ACTION"); // 当前版本不认识的枚举名（模拟新版本写入）
            ps.setString(6, null);
            ps.setLong(7, now);
            ps.executeUpdate();
        }

        List<AuditEntry> entries = database.findAuditByNickname("alice", 10).get(5, TimeUnit.SECONDS);
        assertEquals(1, entries.size(), "应查到刚写入的那条记录");
        assertEquals(AuditAction.UNKNOWN, entries.get(0).action(),
                "无法识别的 action 必须显示为「未知事件」，不能伪装成管理员操作");
    }
}
