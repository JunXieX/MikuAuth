package cn.miku.auth.migrate;

import cn.miku.auth.audit.AuditLogger;
import cn.miku.auth.config.MikuConfig;
import cn.miku.auth.database.DatabaseManager;
import cn.miku.auth.database.StoredPlayer;
import cn.miku.auth.security.PasswordHasher;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 账号迁移的端到端测试。
 *
 * <p>测试方式：按各插件的<b>真实表结构</b>在临时目录里造一个 SQLite 源库，
 * 跑完整迁移流程，最后断言"目标库里出现该账号，且<b>原密码仍然可以登录</b>"。
 * 这比只测映射函数更有价值——它覆盖了"能不能真的把玩家搬过来"这个唯一重要的问题。
 */
class AccountMigratorTest {

    /** 真实 AuthMe 哈希向量：密码 pantof。 */
    private static final String AUTHME_HASH =
            "$SHA$c7dedf5a36c4a343$05ae3239eee683872ef1cc9096777bf4b1a72a179709efc17d8bf1603b082065";

    @TempDir
    Path tempDir;

    private MikuConfig config;
    private DatabaseManager target;
    private AccountMigrator migrator;

    /**
     * 关闭数据库与迁移线程。
     *
     * <p>必须显式关闭：SQLite 连接未释放时 Windows 会占用文件，
     * JUnit 清理临时目录会失败（表现为"测试全挂"，实为清理阶段问题）。
     */
    @AfterEach
    void tearDown() {
        if (migrator != null) {
            migrator.shutdown();
        }
        if (target != null) {
            target.close();
        }
    }

    @BeforeEach
    void setUp() throws Exception {
        Files.writeString(tempDir.resolve("config.yml"), """
                server:
                  auth-server: "auth"
                premium:
                  enabled: false
                """, StandardCharsets.UTF_8);
        config = new MikuConfig();
        config.load(tempDir, null);

        target = new DatabaseManager(tempDir.resolve("target"), config,
                org.slf4j.helpers.NOPLogger.NOP_LOGGER);
        migrator = new AccountMigrator(target,
                new AuditLogger(target, config, org.slf4j.helpers.NOPLogger.NOP_LOGGER),
                org.slf4j.helpers.NOPLogger.NOP_LOGGER);
    }

    // ---------------------------------------------------------------------
    // AuthMe
    // ---------------------------------------------------------------------

    @Test
    void migratesAuthMeAccountsAndKeepsOriginalPasswordWorking() throws Exception {
        Path source = createAuthMeDatabase("""
                INSERT INTO authme (username, realname, password, ip, regdate, lastlogin) VALUES
                    ('alice', 'Alice', '%s', '1.2.3.4', 1700000000000, 1700000100000),
                    ('bob', 'Bob', '%s', NULL, 0, 0)
                """.formatted(AUTHME_HASH, AUTHME_HASH));

        MigrationReport report = migrator.migrateAsync(
                MigrationSource.AUTHME, "sqlite:" + source, false).join();

        assertEquals(2, report.total());
        assertEquals(2, report.imported());
        assertEquals(0, report.skipped());
        assertEquals(0, report.noPassword());

        StoredPlayer alice = target.findPlayer("Alice").join().orElseThrow();
        assertEquals("1.2.3.4", alice.registerIp(), "注册 IP 应一并迁移");
        assertEquals(1700000000000L, alice.registerTime(), "注册时间应保留源库值");
        assertFalse(alice.isPremiumType(), "迁移一律按离线账号导入");
        assertTrue(PasswordHasher.verify("pantof", alice.passwordHash()),
                "★ 关键：迁移后玩家用原密码必须能登录");
    }

    @Test
    void secondRunSkipsExistingAccounts() throws Exception {
        Path source = createAuthMeDatabase("""
                INSERT INTO authme (username, realname, password, ip, regdate, lastlogin) VALUES
                    ('alice', 'Alice', '%s', '1.2.3.4', 0, 0)
                """.formatted(AUTHME_HASH));

        migrator.migrateAsync(MigrationSource.AUTHME, "sqlite:" + source, false).join();
        MigrationReport second = migrator.migrateAsync(
                MigrationSource.AUTHME, "sqlite:" + source, false).join();

        assertEquals(1, second.total());
        assertEquals(0, second.imported());
        assertEquals(1, second.skipped(), "已存在的账号必须跳过，绝不覆盖");
    }

    @Test
    void dryRunWritesNothing() throws Exception {
        Path source = createAuthMeDatabase("""
                INSERT INTO authme (username, realname, password, ip, regdate, lastlogin) VALUES
                    ('alice', 'Alice', '%s', '1.2.3.4', 0, 0)
                """.formatted(AUTHME_HASH));

        MigrationReport report = migrator.migrateAsync(
                MigrationSource.AUTHME, "sqlite:" + source, true).join();

        assertTrue(report.dryRun());
        assertEquals(1, report.total(), "试运行也应统计到条数");
        assertEquals(0, report.imported());
        assertTrue(target.findPlayer("Alice").join().isEmpty(), "试运行绝不能写入目标库");
    }

    @Test
    void reportsAccountsWhosePasswordCannotBeReused() throws Exception {
        Path source = createAuthMeDatabase("""
                INSERT INTO authme (username, realname, password, ip, regdate, lastlogin) VALUES
                    ('carol', 'Carol', '$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA', '1.2.3.4', 0, 0)
                """);

        MigrationReport report = migrator.migrateAsync(
                MigrationSource.AUTHME, "sqlite:" + source, false).join();

        assertEquals(1, report.total());
        assertEquals(1, report.noPassword(), "不支持的算法应被明确计数，而不是静默失败");
        // 账号本身仍然迁入（昵称、IP 保留），只是密码为空 → 玩家需重新设置
        StoredPlayer stored = target.findPlayer("Carol").join().orElseThrow();
        assertEquals(null, stored.passwordHash());
    }

    // ---------------------------------------------------------------------
    // LimboAuth
    // ---------------------------------------------------------------------

    @Test
    void migratesLimboAuthAccountsReusingTheirUuid() throws Exception {
        String bcrypt = PasswordHasher.hash("secret-pass", 10);
        String uuid = "11111111-2222-3333-4444-555555555555";
        Path source = createLimboAuthDatabase("""
                INSERT INTO AUTH (LAST_NICKNAME, LOWERCASE_NICKNAME, PASSWORD, IP, REGDATE, LAST_SEEN, UUID)
                VALUES ('Dave', 'dave', '%s', '5.6.7.8', 1700000000000, 1700000900000, '%s')
                """.formatted(bcrypt, uuid));

        MigrationReport report = migrator.migrateAsync(
                MigrationSource.LIMBOAUTH, "sqlite:" + source, false).join();

        assertEquals(1, report.imported());
        StoredPlayer dave = target.findPlayer("Dave").join().orElseThrow();
        assertEquals(uuid, dave.uuid().toString(), "LimboAuth 存有 UUID，应原样沿用（避开改名漂移）");
        assertTrue(PasswordHasher.verify("secret-pass", dave.passwordHash()));
    }

    // ---------------------------------------------------------------------
    // LibreLogin
    // ---------------------------------------------------------------------

    @Test
    void migratesLibreLoginAccounts() throws Exception {
        String bcrypt = PasswordHasher.hash("libre-pass", 10);
        String uuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        Path source = createLibreLoginDatabase("""
                INSERT INTO librepremium_data
                    (uuid, last_nickname, hashed_password, salt, algo, ip, joined, last_seen)
                VALUES ('%s', 'Eve', '%s', NULL, 'BCRYPT', '9.9.9.9',
                        '2024-01-01 10:00:00', '2024-02-01 12:00:00')
                """.formatted(uuid, bcrypt));

        MigrationReport report = migrator.migrateAsync(
                MigrationSource.LIBRELOGIN, "sqlite:" + source, false).join();

        assertEquals(1, report.imported());
        StoredPlayer eve = target.findPlayer("Eve").join().orElseThrow();
        assertEquals(uuid, eve.uuid().toString());
        assertTrue(PasswordHasher.verify("libre-pass", eve.passwordHash()));
        assertTrue(eve.registerTime() > 0, "注册时间应由 joined 时间戳转换而来");
    }

    // ---------------------------------------------------------------------
    // 连接串解析
    // ---------------------------------------------------------------------

    @Test
    void parsesSupportedLocationFormats() {
        assertEquals("jdbc:sqlite:/srv/auths.db",
                AccountMigrator.jdbcUrl("sqlite:/srv/auths.db"));
        assertEquals("jdbc:sqlite:./auths.db",
                AccountMigrator.jdbcUrl("./auths.db"), "裸路径应按 SQLite 文件处理");
        assertEquals("jdbc:sqlite:C:/servers/authme.db",
                AccountMigrator.jdbcUrl("sqlite:C:/servers/authme.db"), "Windows 路径不应被截断");
        assertEquals("jdbc:mariadb://db.local:3306/authme?user=root&password=secret",
                AccountMigrator.jdbcUrl("mysql://root:secret@db.local:3306/authme"));
        assertEquals("jdbc:mariadb://db.local:3306/authme?user=root&password=secret",
                AccountMigrator.jdbcUrl("mariadb://root:secret@db.local:3306/authme"));
        assertEquals("jdbc:sqlite:/given.db",
                AccountMigrator.jdbcUrl("jdbc:sqlite:/given.db"));
    }

    // ---------------------------------------------------------------------
    // 造库工具
    // ---------------------------------------------------------------------

    private Path createAuthMeDatabase(String insertSql) throws Exception {
        Path path = tempDir.resolve("authme-source.db");
        try (Connection connection = openSqlite(path); Statement statement = connection.createStatement()) {
            statement.execute("""
                    CREATE TABLE authme (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username VARCHAR(255) NOT NULL,
                        realname VARCHAR(255) NOT NULL,
                        password VARCHAR(255) NOT NULL,
                        ip VARCHAR(40),
                        regdate INTEGER,
                        lastlogin INTEGER
                    )""");
            for (String sql : insertSql.split(";\n")) {
                if (!sql.isBlank()) {
                    statement.execute(sql);
                }
            }
        }
        return path;
    }

    private Path createLimboAuthDatabase(String insertSql) throws Exception {
        Path path = tempDir.resolve("limboauth-source.db");
        try (Connection connection = openSqlite(path); Statement statement = connection.createStatement()) {
            statement.execute("""
                    CREATE TABLE AUTH (
                        LAST_NICKNAME      VARCHAR(16) NOT NULL,
                        LOWERCASE_NICKNAME VARCHAR(16) NOT NULL,
                        PASSWORD           VARCHAR(255),
                        IP                 VARCHAR(45),
                        REGDATE            BIGINT,
                        LAST_SEEN          BIGINT,
                        UUID               VARCHAR(36),
                        PREMIUM_UUID       VARCHAR(36)
                    )""");
            statement.execute(insertSql);
        }
        return path;
    }

    private Path createLibreLoginDatabase(String insertSql) throws Exception {
        Path path = tempDir.resolve("librelogin-source.db");
        try (Connection connection = openSqlite(path); Statement statement = connection.createStatement()) {
            statement.execute("""
                    CREATE TABLE librepremium_data (
                        uuid            VARCHAR(255) PRIMARY KEY,
                        premium_uuid    VARCHAR(255),
                        hashed_password VARCHAR(255),
                        salt            VARCHAR(255),
                        algo            VARCHAR(255),
                        last_nickname   VARCHAR(255) NOT NULL,
                        joined          TIMESTAMP,
                        last_seen       TIMESTAMP,
                        ip              VARCHAR(255)
                    )""");
            statement.execute(insertSql);
        }
        return path;
    }

    private static Connection openSqlite(Path path) throws Exception {
        Class.forName("org.sqlite.JDBC");
        return DriverManager.getConnection("jdbc:sqlite:" + path);
    }

    /** 供未来扩展的守卫：确保迁移源解析与提示文案保持一致。 */
    @Test
    void parsesAllSupportedSourceNames() {
        assertEquals(MigrationSource.AUTHME, MigrationSource.parse("AuthMe"));
        assertEquals(MigrationSource.LIBRELOGIN, MigrationSource.parse("librelogin"));
        assertEquals(MigrationSource.LIMBOAUTH, MigrationSource.parse("LIMBOAUTH"));
        assertNotNull(MigrationSource.usage());
        assertEquals(null, MigrationSource.parse("unknown-plugin"));
    }
}
