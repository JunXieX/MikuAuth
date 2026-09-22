package cn.miku.auth.database;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;

/**
 * SQLite 后端：单文件、单连接。
 *
 * <p>{@link DatabaseManager} 会用<b>单线程</b>执行器串行化所有操作，因此这里可以安全地
 * 复用同一个连接：既避免并发写冲突（SQLITE_BUSY），也不需要连接池开销。
 */
final class SqliteBackend implements SqlBackend {

    private final Connection connection;
    private final Path dbFile;

    SqliteBackend(Path dataDirectory, String databaseFile, org.slf4j.Logger logger)
            throws SQLException, IOException {
        Files.createDirectories(dataDirectory);
        // 数据库文件名同样要防越界：database.file 指向数据目录之外时，
        // 等于允许配置在任意路径创建/覆盖 SQLite 文件
        this.dbFile = cn.miku.auth.util.PathSafety.resolveInside(
                dataDirectory, databaseFile, "mikuauth.db", logger);
        try {
            // 显式注册驱动：Velocity 的插件类加载器下 DriverManager 的
            // ServiceLoader 自动发现不可靠，必须手动加载一次
            Class.forName("org.sqlite.JDBC");
        } catch (ClassNotFoundException e) {
            throw new SQLException("未找到 SQLite JDBC 驱动", e);
        }
        this.connection = DriverManager.getConnection("jdbc:sqlite:" + dbFile.toAbsolutePath());
        configure();
    }

    /** 设置 SQLite 性能参数。 */
    private void configure() throws SQLException {
        try (Statement statement = connection.createStatement()) {
            // PRAGMA 语句会返回结果行，用 execute 而非 executeUpdate 语义更准确
            statement.execute("PRAGMA journal_mode=WAL");
            statement.execute("PRAGMA synchronous=NORMAL");
            statement.execute("PRAGMA busy_timeout=5000");
        }
    }

    @Override
    public Connection borrow() {
        return connection;
    }

    @Override
    public void release(Connection ignored) {
        // 共享连接，无需归还
    }

    @Override
    public String playersDdl(String tableName) {
        return """
                CREATE TABLE IF NOT EXISTS %s (
                    uuid            TEXT PRIMARY KEY,
                    nickname_lower  TEXT NOT NULL UNIQUE,
                    display_name    TEXT NOT NULL,
                    password_hash   TEXT,
                    auth_type       TEXT NOT NULL,
                    register_ip     TEXT,
                    register_time   INTEGER,
                    last_login_ip   TEXT,
                    last_login_time INTEGER
                )""".formatted(tableName);
    }

    @Override
    public void swapPlayersTable(Connection connection, String migratingTable) throws SQLException {
        // SQLite 不支持一条语句重命名多张表；DDL 在事务内可回滚，先删后改是安全的
        try (Statement statement = connection.createStatement()) {
            statement.executeUpdate("DROP TABLE miku_players");
            statement.executeUpdate("ALTER TABLE " + migratingTable + " RENAME TO miku_players");
        }
    }

    @Override
    public List<String> schemaStatements() {
        return List.of(
                playersDdl("miku_players"),
                """
                CREATE TABLE IF NOT EXISTS miku_sessions (
                    nickname_lower TEXT PRIMARY KEY,
                    ip             TEXT NOT NULL,
                    expires_at     INTEGER NOT NULL
                )""",
                "CREATE INDEX IF NOT EXISTS idx_players_register_ip ON miku_players (register_ip)",
                "CREATE INDEX IF NOT EXISTS idx_players_last_ip ON miku_players (last_login_ip)",
                "CREATE INDEX IF NOT EXISTS idx_sessions_expires ON miku_sessions (expires_at)",
                auditLogDdl("miku_audit_log"),
                "CREATE INDEX IF NOT EXISTS idx_audit_nickname ON miku_audit_log (nickname_lower, created_at)",
                "CREATE INDEX IF NOT EXISTS idx_audit_created ON miku_audit_log (created_at)",
                // /mikuauth audit ip <IP> 用得上：没有它时每次查询都是全表扫描 + 排序
                "CREATE INDEX IF NOT EXISTS idx_audit_ip ON miku_audit_log (ip, id)");
    }

    @Override
    public String purgeSessionsSql() {
        return "DELETE FROM miku_sessions WHERE nickname_lower IN "
                + "(SELECT nickname_lower FROM miku_sessions WHERE expires_at <= ? LIMIT ?)";
    }

    @Override
    public String purgeAuditSql() {
        return "DELETE FROM miku_audit_log WHERE id IN "
                + "(SELECT id FROM miku_audit_log WHERE created_at < ? LIMIT ?)";
    }

    @Override
    public String upsertSessionSql() {
        return """
                INSERT INTO miku_sessions (nickname_lower, ip, expires_at) VALUES (?, ?, ?)
                ON CONFLICT(nickname_lower) DO UPDATE SET ip = excluded.ip, expires_at = excluded.expires_at""";
    }

    @Override
    public String insertIgnorePlayerSql() {
        return """
                INSERT OR IGNORE INTO miku_players
                    (uuid, nickname_lower, display_name, password_hash, auth_type,
                     register_ip, register_time, last_login_ip, last_login_time)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""";
    }

    @Override
    public String auditLogDdl(String tableName) {
        return """
                CREATE TABLE IF NOT EXISTS %s (
                    id             INTEGER PRIMARY KEY AUTOINCREMENT,
                    nickname       TEXT    NOT NULL,
                    nickname_lower TEXT    NOT NULL,
                    uuid           TEXT,
                    ip             TEXT,
                    action         TEXT    NOT NULL,
                    detail         TEXT,
                    created_at     INTEGER NOT NULL
                )""".formatted(tableName);
    }

    @Override
    public int workerThreads() {
        return 1;
    }

    @Override
    public String describe() {
        return "SQLite (" + dbFile + ")";
    }

    @Override
    public void close() {
        try {
            connection.close();
        } catch (SQLException ignored) {
            // 关闭失败无需处理
        }
    }
}
