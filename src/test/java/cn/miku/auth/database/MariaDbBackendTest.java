package cn.miku.auth.database;

import cn.miku.auth.config.MikuConfig;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * MariaDB 后端的集成测试：验证方言差异最大的几处（建表 DDL、会话 upsert、
 * 唯一冲突识别、设备表清理），这些正是 SQLite 测试覆盖不到的部分。
 *
 * <p>默认<b>跳过</b>（本机没有 MariaDB 时不应让构建失败）。指定连接参数即可运行：
 * <pre>
 * mvn test -Dmikuauth.test.mariadb.host=127.0.0.1 \
 *          -Dmikuauth.test.mariadb.user=mikuauth \
 *          -Dmikuauth.test.mariadb.password=你的密码 \
 *          [-Dmikuauth.test.mariadb.database=mikuauth_test] \
 *          [-Dmikuauth.test.mariadb.port=3306]
 * </pre>
 * 测试会在该库中建表并在每个用例前后清空 miku_* 表，请务必指向<b>专用测试库</b>。
 */
class MariaDbBackendTest {

    private static final String HOST = System.getProperty("mikuauth.test.mariadb.host", "");
    private static final String PORT = System.getProperty("mikuauth.test.mariadb.port", "3306");
    private static final String DATABASE = System.getProperty("mikuauth.test.mariadb.database", "mikuauth_test");
    private static final String USER = System.getProperty("mikuauth.test.mariadb.user", "mikuauth");
    private static final String PASSWORD = System.getProperty("mikuauth.test.mariadb.password", "");

    @TempDir
    Path tempDir;

    private DatabaseManager database;

    @BeforeAll
    static void requireConfiguredServer() {
        Assumptions.assumeTrue(!HOST.isBlank(),
                "未提供 -Dmikuauth.test.mariadb.host，跳过 MariaDB 集成测试");
    }

    @BeforeEach
    void setUp() throws Exception {
        Files.writeString(tempDir.resolve("config.yml"), """
                database:
                  type: "mariadb"
                  mariadb:
                    host: "%s"
                    port: %s
                    database: "%s"
                    username: "%s"
                    password: "%s"
                    pool-size: 3
                    connection-timeout-millis: 5000
                    ssl-mode: "disable"
                """.formatted(HOST, PORT, DATABASE, USER, PASSWORD), StandardCharsets.UTF_8);

        MikuConfig config = new MikuConfig();
        config.load(tempDir, null);
        truncateAll();
        database = new DatabaseManager(tempDir, config, LoggerFactory.getLogger("MikuAuthMariaDbTest"));
    }

    @AfterEach
    void tearDown() throws Exception {
        if (database != null) {
            database.close();
            database = null;
        }
        truncateAll();
    }

    /** 直接连库清空 miku_* 表（建表由 DatabaseManager 负责）。 */
    private static void truncateAll() throws Exception {
        try (Connection connection = DriverManager.getConnection(
                "jdbc:mariadb://" + HOST + ":" + PORT + "/" + DATABASE + "?sslMode=disable",
                USER, PASSWORD);
             Statement statement = connection.createStatement()) {
            for (String table : new String[]{"miku_players", "miku_sessions"}) {
                try {
                    statement.executeUpdate("DELETE FROM " + table);
                } catch (Exception ignored) {
                    // 首次运行时表还不存在
                }
            }
        }
    }

    @Test
    void schemaIsCreatedAndCrudWorks() throws Exception {
        assertEquals(DatabaseManager.RegisterResult.OK,
                database.register(UUID.randomUUID(), "Alice", "hash", StoredPlayer.TYPE_OFFLINE, "10.0.0.1")
                        .get(5, TimeUnit.SECONDS));

        Optional<StoredPlayer> found = database.findPlayer("alice").get(5, TimeUnit.SECONDS);
        assertTrue(found.isPresent());
        assertEquals("Alice", found.get().nickname());
    }

    @Test
    void duplicateRegistrationIsDetectedFromMariaDbError() throws Exception {
        database.register(UUID.randomUUID(), "Alice", "hash", StoredPlayer.TYPE_OFFLINE, "10.0.0.1")
                .get(5, TimeUnit.SECONDS);
        // MariaDB 的报错文案是 "Duplicate entry ... for key ..."，必须与 SQLite 一样被识别为重复
        assertEquals(DatabaseManager.RegisterResult.DUPLICATE,
                database.register(UUID.randomUUID(), "Alice", "hash2", StoredPlayer.TYPE_OFFLINE, "10.0.0.1")
                        .get(5, TimeUnit.SECONDS));
    }

    @Test
    void sessionUpsertUsesMariaDbSyntax() throws Exception {
        long first = System.currentTimeMillis() + 60_000L;
        database.saveSession("Alice", "10.0.0.1", first).get(5, TimeUnit.SECONDS);

        // 同一主键二次写入必须走 ON DUPLICATE KEY UPDATE，而不是报主键冲突
        long second = first + 60_000L;
        database.saveSession("Alice", "10.0.0.2", second).get(5, TimeUnit.SECONDS);

        DatabaseManager.Session session = database.findSession("Alice").get(5, TimeUnit.SECONDS).orElseThrow();
        assertEquals("10.0.0.2", session.ip());
        assertEquals(second, session.expiresAt());
        assertEquals(0, database.purgeExpiredSessions().get(5, TimeUnit.SECONDS));
    }

    @Test
    void premiumBindingAndIpQuotaWork() throws Exception {
        database.register(UUID.randomUUID(), "Offline1", "hash", StoredPlayer.TYPE_OFFLINE, "10.0.0.1")
                .get(5, TimeUnit.SECONDS);
        database.register(UUID.randomUUID(), "Premium1", null, StoredPlayer.TYPE_PREMIUM, "10.0.0.1")
                .get(5, TimeUnit.SECONDS);

        // 正版账号不计入 IP 配额
        assertEquals(1, database.countAccountsByIp("10.0.0.1").get(5, TimeUnit.SECONDS));
        assertEquals(2, database.findAccountsByIp("10.0.0.1").get(5, TimeUnit.SECONDS).size());

        assertTrue(database.clearPremiumBinding("Premium1").get(5, TimeUnit.SECONDS));
        StoredPlayer after = database.findPlayer("Premium1").get(5, TimeUnit.SECONDS).orElseThrow();
        assertFalse(after.isPremiumType());
    }
}
