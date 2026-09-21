package cn.miku.auth.database;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import org.slf4j.Logger;

/**
 * MariaDB 后端：网络数据库 + 连接池（HikariCP）。
 *
 * <p>与 SQLite 的关键差异：
 * <ul>
 *   <li>连接来自池，操作可以并发；{@link #workerThreads()} 与池大小一致，
 *       保证提交的任务总能立刻拿到连接（不会在池上排队等待）；</li>
 *   <li>建表语句必须给出长度（MariaDB 不允许 TEXT 作主键），时间戳用 BIGINT，
 *       引擎/字符集显式指定，避免依赖服务端默认值；</li>
 *   <li>upsert 语法为 {@code ON DUPLICATE KEY UPDATE}。</li>
 * </ul>
 *
 * <p>表名固定 {@code miku_*}，请使用独立 database。
 */
final class MariaDbBackend implements SqlBackend {

    /** 连接参数快照（来自 config.yml 的 database.mariadb 段）。 */
    record Settings(String host, int port, String database, String username, String password,
                    String sslMode, int poolSize, int connectionTimeoutMillis) {

        /** 拼接 JDBC URL。驱动侧超时也一并设置，避免单条查询永久挂住。 */
        String jdbcUrl() {
            return "jdbc:mariadb://" + host + ":" + port + "/" + database
                    + "?sslMode=" + sslMode
                    + "&connectTimeout=" + connectionTimeoutMillis
                    + "&socketTimeout=30000";
        }

        /** 日志用描述（不含账号密码）。 */
        String describeTarget() {
            return host + ":" + port + "/" + database;
        }
    }

    private final HikariDataSource dataSource;
    private final Settings settings;

    MariaDbBackend(Settings settings, Logger logger) throws SQLException {
        this.settings = settings;
        try {
            // 与 SQLite 同理：插件类加载器下 ServiceLoader 自动发现不可靠，显式加载一次
            Class.forName("org.mariadb.jdbc.Driver");
        } catch (ClassNotFoundException e) {
            throw new SQLException("未找到 MariaDB JDBC 驱动", e);
        }

        HikariConfig config = new HikariConfig();
        config.setJdbcUrl(settings.jdbcUrl());
        config.setUsername(settings.username());
        config.setPassword(settings.password());
        config.setDriverClassName("org.mariadb.jdbc.Driver");
        config.setPoolName("MikuAuth-MariaDB");
        config.setMaximumPoolSize(settings.poolSize());
        config.setMinimumIdle(Math.min(2, settings.poolSize()));
        // 等待池中空闲连接的上限（区别于驱动侧的 connectTimeout）
        config.setConnectionTimeout(settings.connectionTimeoutMillis());
        config.setValidationTimeout(Math.max(1000, settings.connectionTimeoutMillis() / 2));
        config.setAutoCommit(true);
        config.setMaxLifetime(30 * 60_000L);
        config.setIdleTimeout(10 * 60_000L);
        // 连接初始化失败时不要吞掉异常：构造期直接抛 SQLException 让插件明确报错
        config.setInitializationFailTimeout(settings.connectionTimeoutMillis());

        try {
            this.dataSource = new HikariDataSource(config);
        } catch (RuntimeException e) {
            // 把连接池的原始异常包装成带"目标 + 排查建议"的 SQLException，
            // 否则插件停用时日志里只有一句 HikariPool 的内部报错，服主无从下手
            throw new SQLException("无法连接 MariaDB " + settings.describeTarget()
                    + "（请检查 database.mariadb 的 host/port/账号密码，以及数据库是否已启动）: "
                    + e.getMessage(), e);
        }
        if (logger != null) {
            logger.info("[数据库] MariaDB 连接池已就绪（{}，池大小 {}）",
                    settings.describeTarget(), settings.poolSize());
        }
    }

    @Override
    public Connection borrow() throws SQLException {
        return dataSource.getConnection();
    }

    @Override
    public void release(Connection connection) {
        if (connection == null) {
            return;
        }
        try {
            connection.close();
        } catch (SQLException ignored) {
            // 归还失败由连接池自行回收
        }
    }

    @Override
    public String playersDdl(String tableName) {
        return """
                CREATE TABLE IF NOT EXISTS %s (
                    uuid            CHAR(36)     NOT NULL,
                    nickname_lower  VARCHAR(16)  NOT NULL,
                    display_name    VARCHAR(16)  NOT NULL,
                    password_hash   VARCHAR(100) NULL,
                    auth_type       VARCHAR(16)  NOT NULL,
                    register_ip     VARCHAR(45)  NULL,
                    register_time   BIGINT       NULL,
                    last_login_ip   VARCHAR(45)  NULL,
                    last_login_time BIGINT       NULL,
                    PRIMARY KEY (uuid),
                    UNIQUE KEY uk_players_nickname (nickname_lower),
                    KEY idx_players_register_ip (register_ip),
                    KEY idx_players_last_ip (last_login_ip)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci""".formatted(tableName);
    }

    @Override
    public void swapPlayersTable(Connection connection, String migratingTable) throws SQLException {
        // MariaDB 支持一条语句原子换名，避免"旧表已删、新表没改成"的中间态
        try (Statement statement = connection.createStatement()) {
            statement.executeUpdate("RENAME TABLE miku_players TO miku_players_legacy, "
                    + migratingTable + " TO miku_players");
            statement.executeUpdate("DROP TABLE miku_players_legacy");
        }
    }

    @Override
    public List<String> schemaStatements() {
        return List.of(
                playersDdl("miku_players"),
                """
                CREATE TABLE IF NOT EXISTS miku_sessions (
                    nickname_lower VARCHAR(16) NOT NULL,
                    ip             VARCHAR(45) NOT NULL,
                    expires_at     BIGINT      NOT NULL,
                    PRIMARY KEY (nickname_lower),
                    KEY idx_sessions_expires (expires_at)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci""",
                auditLogDdl("miku_audit_log"));
    }

    @Override
    public String insertIgnorePlayerSql() {
        return """
                INSERT IGNORE INTO miku_players
                    (uuid, nickname_lower, display_name, password_hash, auth_type,
                     register_ip, register_time, last_login_ip, last_login_time)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""";
    }

    @Override
    public String auditLogDdl(String tableName) {
        return """
                CREATE TABLE IF NOT EXISTS %s (
                    id             BIGINT       NOT NULL AUTO_INCREMENT,
                    nickname       VARCHAR(16)  NOT NULL,
                    nickname_lower VARCHAR(16)  NOT NULL,
                    uuid           CHAR(36)     NULL,
                    ip             VARCHAR(45)  NULL,
                    action         VARCHAR(32)  NOT NULL,
                    detail         VARCHAR(255) NULL,
                    created_at     BIGINT       NOT NULL,
                    PRIMARY KEY (id),
                    KEY idx_audit_nickname (nickname_lower, created_at),
                    KEY idx_audit_created (created_at)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci""".formatted(tableName);
    }

    @Override
    public String upsertSessionSql() {
        return """
                INSERT INTO miku_sessions (nickname_lower, ip, expires_at) VALUES (?, ?, ?)
                ON DUPLICATE KEY UPDATE ip = VALUES(ip), expires_at = VALUES(expires_at)""";
    }

    @Override
    public int workerThreads() {
        return settings.poolSize();
    }

    @Override
    public String describe() {
        return "MariaDB (" + settings.describeTarget() + ")";
    }

    @Override
    public void close() {
        dataSource.close();
    }
}
