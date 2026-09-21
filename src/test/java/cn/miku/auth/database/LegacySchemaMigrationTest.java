package cn.miku.auth.database;

import cn.miku.auth.config.MikuConfig;
import cn.miku.auth.util.UuidUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.LoggerFactory;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 老库结构升级测试：把 2.2.x 及更早版本的"昵称主键"账号表升级为"UUID 主键"。
 *
 * <p>这是本版风险最高的一段逻辑（要重建用户的账号表），因此用真实的旧结构 +
 * 真实数据形态（含同一正版 UUID 的多条改名遗留记录）来验证：
 * 迁移后数据不丢、UUID 正确、重复记录被清理、旧昵称被释放。
 */
class LegacySchemaMigrationTest {

    @TempDir
    Path tempDir;

    private UUID premiumUuid;

    /** 用<b>旧结构</b>建表并插入数据（旧结构：nickname_lower 主键 + premium_uuid 列）。 */
    @BeforeEach
    void createLegacyDatabase() throws Exception {
        premiumUuid = UUID.randomUUID();
        try (Connection connection = DriverManager.getConnection(
                "jdbc:sqlite:" + tempDir.resolve("database.db").toAbsolutePath());
             Statement statement = connection.createStatement()) {
            statement.executeUpdate("""
                    CREATE TABLE miku_players (
                        nickname_lower  TEXT PRIMARY KEY,
                        display_name    TEXT NOT NULL,
                        password_hash   TEXT,
                        auth_type       TEXT NOT NULL,
                        premium_uuid    TEXT,
                        register_ip     TEXT,
                        register_time   INTEGER,
                        last_login_ip   TEXT,
                        last_login_time INTEGER
                    )""");
            statement.executeUpdate("""
                    CREATE TABLE miku_sessions (
                        nickname_lower TEXT PRIMARY KEY,
                        ip             TEXT NOT NULL,
                        expires_at     INTEGER NOT NULL
                    )""");
        }
        // 1) 普通离线账号
        insertLegacy("alice", "Alice", "hash-alice", StoredPlayer.TYPE_OFFLINE, null, "10.0.0.1", 1000);
        // 2) 正版玩家改名前的旧记录（无密码，早于改名）
        insertLegacy("bob", "Bob", null, StoredPlayer.TYPE_PREMIUM, premiumUuid.toString(), "10.0.0.2", 2000);
        // 3) 同一正版 UUID 改名后的新记录（有密码，最近使用）—— 迁移时应保留这条
        insertLegacy("robert", "Robert", "hash-robert", StoredPlayer.TYPE_PREMIUM,
                premiumUuid.toString(), "10.0.0.3", 3000);
    }

    private void insertLegacy(String nicknameLower, String displayName, String hash, String authType,
                              String premiumUuidText, String ip, long lastLoginTime) throws Exception {
        try (Connection connection = DriverManager.getConnection(
                "jdbc:sqlite:" + tempDir.resolve("database.db").toAbsolutePath());
             PreparedStatement ps = connection.prepareStatement("""
                     INSERT INTO miku_players (nickname_lower, display_name, password_hash, auth_type,
                                               premium_uuid, register_ip, register_time,
                                               last_login_ip, last_login_time)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""")) {
            ps.setString(1, nicknameLower);
            ps.setString(2, displayName);
            ps.setString(3, hash);
            ps.setString(4, authType);
            ps.setString(5, premiumUuidText);
            ps.setString(6, ip);
            ps.setLong(7, lastLoginTime);
            ps.setString(8, ip);
            ps.setLong(9, lastLoginTime);
            ps.executeUpdate();
        }
    }

    private DatabaseManager openMigrated() throws Exception {
        MikuConfig config = new MikuConfig();
        config.load(tempDir, null);
        return new DatabaseManager(tempDir, config, LoggerFactory.getLogger("LegacyMigrationTest"));
    }

    private static int countPlayers(Path dir) throws Exception {
        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + dir.resolve("database.db").toAbsolutePath());
             Statement statement = connection.createStatement();
             ResultSet rs = statement.executeQuery("SELECT COUNT(*) FROM miku_players")) {
            return rs.next() ? rs.getInt(1) : -1;
        }
    }

    @Test
    void legacyTableIsMigratedAndDuplicatesAreReleased() throws Exception {
        try (DatabaseManager database = openMigrated()) {
            // 3 条旧记录里有 2 条属于同一正版 UUID → 去重后应为 2 条
            assertEquals(2, countPlayers(tempDir));

            // 离线账号：UUID 由昵称推导
            StoredPlayer alice = database.findPlayer("Alice").get(5, TimeUnit.SECONDS).orElseThrow();
            assertEquals(UuidUtil.offlineUuid("Alice"), alice.uuid());
            assertEquals("hash-alice", alice.passwordHash());

            // 正版账号：保留"有密码的那条"（robert），旧昵称 bob 被释放
            StoredPlayer kept = database.findPlayerByUuid(premiumUuid).get(5, TimeUnit.SECONDS).orElseThrow();
            assertEquals("Robert", kept.nickname());
            assertEquals("hash-robert", kept.passwordHash());
            assertEquals(premiumUuid, kept.premiumUuid());
            assertTrue(database.findPlayer("Bob").get(5, TimeUnit.SECONDS).isEmpty(),
                    "旧昵称应被释放，可被其他玩家使用");
        }
    }

    @Test
    void migratedTableHasUuidPrimaryKeyAndUniqueNickname() throws Exception {
        try (DatabaseManager database = openMigrated()) {
            // 新结构：uuid 主键 + nickname_lower 唯一索引
            assertTrue(columnExists("uuid"), "应新增 uuid 列");
            assertFalse(columnExists("premium_uuid"), "旧的 premium_uuid 列应被移除");
            assertTrue(indexExists("sqlite_autoindex_miku_players_1")
                            || indexExists("sqlite_autoindex_miku_players_2"),
                    "昵称唯一约束应生效");

            // 同名不同 UUID 的注册必须被唯一约束挡住（否则会出现两个账号抢一个昵称）
            assertEquals(DatabaseManager.RegisterResult.DUPLICATE,
                    database.register(UUID.randomUUID(), "Alice", "hash", StoredPlayer.TYPE_OFFLINE, "10.0.0.9")
                            .get(5, TimeUnit.SECONDS));
        }
    }

    @Test
    void migrationIsIdempotent() throws Exception {
        try (DatabaseManager first = openMigrated()) {
            assertEquals(2, countPlayers(tempDir));
        }
        // 二次启动：已是新结构，不应再次迁移、也不应改变数据
        try (DatabaseManager second = openMigrated()) {
            assertEquals(2, countPlayers(tempDir));
            assertTrue(second.findPlayerByUuid(premiumUuid).get(5, TimeUnit.SECONDS).isPresent());
        }
    }

    private boolean columnExists(String column) throws Exception {
        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + tempDir.resolve("database.db").toAbsolutePath());
             Statement statement = connection.createStatement();
             ResultSet rs = statement.executeQuery("PRAGMA table_info(miku_players)")) {
            while (rs.next()) {
                if (column.equalsIgnoreCase(rs.getString("name"))) {
                    return true;
                }
            }
            return false;
        }
    }

    private boolean indexExists(String name) throws Exception {
        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + tempDir.resolve("database.db").toAbsolutePath());
             Statement statement = connection.createStatement();
             ResultSet rs = statement.executeQuery(
                     "SELECT name FROM sqlite_master WHERE type='index' AND name='" + name + "'")) {
            return rs.next();
        }
    }
}
