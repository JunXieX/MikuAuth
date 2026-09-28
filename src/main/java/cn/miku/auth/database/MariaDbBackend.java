package cn.miku.auth.database;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;

import java.sql.Connection;
import java.sql.Driver;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import java.util.Properties;
import org.slf4j.Logger;

/**
 * MariaDB / MySQL 后端：网络数据库 + 连接池（HikariCP）。
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
 * <p>两种方言都由本类承担（表结构 / upsert / 清理 SQL 完全一致）：区别仅在
 * JDBC URL 前缀、驱动（MySQL Connector/J 与 MariaDB Connector/J）与 TLS 参数名。
 * 驱动不再随插件打包，由 {@link JdbcDriverLoader} 按需装载后通过
 * {@code HikariConfig#setDriver} 直接交给连接池。
 *
 * <p>表名固定 {@code miku_*}，请使用独立 database。
 */
final class MariaDbBackend implements SqlBackend {

    /** 连接参数快照（来自 config.yml 的 database.mariadb 段）。 */
    record Settings(String type, String host, int port, String database, String username, String password,
                    String sslMode, int poolSize, int connectionTimeoutMillis) {

        /** 驱动规格（mariadb / mysql）。 */
        JdbcDriverLoader.DriverSpec driverSpec() {
            return "mysql".equals(type)
                    ? JdbcDriverLoader.MYSQL
                    : JdbcDriverLoader.MARIADB;
        }

        /** JDBC URL 前缀（mysql 类型用 jdbc:mysql）。 */
        String jdbcPrefix() {
            return "mysql".equals(type) ? "jdbc:mysql://" : "jdbc:mariadb://";
        }

        /**
         * 拼接 JDBC URL。两个驱动的 TLS 参数名都是 {@code sslMode}，
         * 但取值语义不同，这里按目标驱动做映射：
         * <ul>
         *   <li>MariaDB：{@code disable / trust / verify-ca / verify-full}</li>
         *   <li>MySQL：{@code DISABLED / PREFERRED / REQUIRED / VERIFY_CA / VERIFY_IDENTITY}</li>
         * </ul>
         */
        String jdbcUrl() {
            String ssl = "mysql".equals(type) ? mysqlSslMode() : sslMode;
            return jdbcPrefix() + host + ":" + port + "/" + database
                    + "?sslMode=" + ssl
                    + "&connectTimeout=" + connectionTimeoutMillis
                    + "&socketTimeout=30000";
        }

        private String mysqlSslMode() {
            return switch (sslMode) {
                case "trust" -> "REQUIRED";         // 强制 TLS，但不校验证书（对齐 MariaDB 的 trust）
                case "verify-ca" -> "VERIFY_CA";    // 校验服务端证书
                case "verify-full" -> "VERIFY_IDENTITY"; // 校验证书 + 主机名
                default -> "DISABLED";              // disable 及一切非法值
            };
        }

        /** 日志用描述（不含账号密码）。 */
        String describeTarget() {
            return host + ":" + port + "/" + database;
        }
    }

    private final HikariDataSource dataSource;
    private final Settings settings;
    private final Logger logger;

    MariaDbBackend(Settings settings, JdbcDriverLoader driverLoader, Logger logger) throws SQLException {
        this.settings = settings;
        this.logger = logger;
        // 驱动不再随插件打包：按需装载（类路径 → libs/ 缓存 → 镜像下载），
        // 再包装成 DataSource 注入连接池（见下方 dataSourceFor 的说明）
        Driver driver = driverLoader.driver(settings.driverSpec());

        HikariConfig config = new HikariConfig();
        // HikariCP 5.x 没有"直接接收 Driver 实例"的入口（无 setDriver；setDriverClassName 由它
        // 自己的类加载器加载驱动类，看不到按需装载的驱动），因此把驱动包成最小 DataSource
        // 交给 setDataSource —— 这是唯一不依赖类加载可见性的注入方式。
        // 不设 jdbcUrl / driverClassName：建连参数全部由该 DataSource 承担。
        config.setDataSource(dataSourceFor(driver, settings.jdbcUrl()));
        config.setUsername(settings.username());
        config.setPassword(settings.password());
        config.setPoolName("MikuAuth-" + settings.driverSpec().id().toUpperCase(java.util.Locale.ROOT));
        config.setMaximumPoolSize(settings.poolSize());
        config.setMinimumIdle(Math.min(2, settings.poolSize()));
        // 等待池中空闲连接的上限（区别于驱动侧的 connectTimeout）
        config.setConnectionTimeout(settings.connectionTimeoutMillis());
        // Hikari 要求 validationTimeout <= connectionTimeout，否则会告警并自行回退；
        // 而 connection-timeout-millis 允许配到 500ms，硬取 max(1000, ...) 会越界
        config.setValidationTimeout(Math.min(settings.connectionTimeoutMillis(),
                Math.max(1000, settings.connectionTimeoutMillis() / 2)));
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
            throw new SQLException("无法连接 " + settings.driverSpec().id() + " " + settings.describeTarget()
                    + "（请检查 database.mariadb 的 host/port/账号密码，以及数据库是否已启动）: "
                    + e.getMessage(), e);
        }
        if (logger != null) {
            logger.info("[数据库] {} 连接池已就绪（{}，池大小 {}）",
                    settings.driverSpec().id(), settings.describeTarget(), settings.poolSize());
        }
    }

    @Override
    public Connection borrow() throws SQLException {
        return dataSource.getConnection();
    }

    /**
     * 把按需装载的 {@link Driver} 实例包装成一个最小 {@code DataSource} 交给 HikariCP。
     *
     * <p>Hikari 在有 DataSource 时走 {@code getConnection(user, password)}（配置里给了账号），
     * 这里就用这两个参数调 {@code driver.connect(...)}；其余 DataSource 接口方法只是占位。
     */
    private static javax.sql.DataSource dataSourceFor(Driver driver, String jdbcUrl) {
        return new javax.sql.DataSource() {
            @Override
            public Connection getConnection() throws SQLException {
                return connect(null, null);
            }

            @Override
            public Connection getConnection(String username, String password) throws SQLException {
                return connect(username, password);
            }

            private Connection connect(String username, String password) throws SQLException {
                Properties properties = new Properties();
                if (username != null) {
                    properties.setProperty("user", username);
                }
                if (password != null) {
                    properties.setProperty("password", password);
                }
                Connection connection = driver.connect(jdbcUrl, properties);
                if (connection == null) {
                    throw new SQLException("驱动拒绝连接串: " + jdbcUrl);
                }
                return connection;
            }

            @Override
            public java.io.PrintWriter getLogWriter() {
                return null;
            }

            @Override
            public void setLogWriter(java.io.PrintWriter out) {
                // 日志由 HikariCP 负责，这里无需实现
            }

            @Override
            public void setLoginTimeout(int seconds) {
                // 连接超时通过 JDBC URL 参数（connectTimeout）设置
            }

            @Override
            public int getLoginTimeout() {
                return 0;
            }

            @Override
            public java.util.logging.Logger getParentLogger() throws java.sql.SQLFeatureNotSupportedException {
                throw new java.sql.SQLFeatureNotSupportedException("不暴露 JUL 日志器");
            }

            @Override
            public <T> T unwrap(Class<T> iface) throws SQLException {
                throw new SQLException("不支持 unwrap: " + iface);
            }

            @Override
            public boolean isWrapperFor(Class<?> iface) {
                return false;
            }
        };
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
        // 与 MariaDB 一致：一条语句原子换名，旧表保留为带时间戳的备份表。
        // MySQL/MariaDB 的 DDL 会隐式提交，因此"事务里换表"并不构成可回滚的操作。
        String backup = backupTableName();
        try (Statement statement = connection.createStatement()) {
            statement.executeUpdate("RENAME TABLE miku_players TO " + backup + ", "
                    + migratingTable + " TO miku_players");
        }
        if (logger != null) {
            logger.warn("[数据库] 升级前的账号表已保留为 {}（确认新表无误后可手动删除）", backup);
        }
    }

    /** 旧表备份名：带时间戳，多次升级不会互相覆盖。 */
    static String backupTableName() {
        return "miku_players_legacy_" + java.time.LocalDateTime.now()
                .format(java.time.format.DateTimeFormatter.ofPattern("yyyyMMddHHmmss"));
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
                auditLogDdl("miku_audit_log"),
                // 老库补索引：表已存在时上面的 CREATE TABLE IF NOT EXISTS 不会补索引。
                // MariaDB 支持 CREATE INDEX IF NOT EXISTS；MySQL 会报"duplicate key name"，
                // 由 DatabaseManager 识别为可忽略的结构错误。
                "CREATE INDEX IF NOT EXISTS idx_audit_ip ON miku_audit_log (ip, id)");
    }

    @Override
    public String purgeSessionsSql() {
        // MySQL/MariaDB 不允许在 IN 子查询里直接用 LIMIT，必须套一层派生表
        return "DELETE FROM miku_sessions WHERE nickname_lower IN (SELECT nickname_lower FROM "
                + "(SELECT nickname_lower FROM miku_sessions WHERE expires_at <= ? LIMIT ?) AS batch)";
    }

    @Override
    public String purgeAuditSql() {
        return "DELETE FROM miku_audit_log WHERE id IN (SELECT id FROM "
                + "(SELECT id FROM miku_audit_log WHERE created_at < ? LIMIT ?) AS batch)";
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
                    KEY idx_audit_created (created_at),
                    KEY idx_audit_ip (ip, id)
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
        return settings.driverSpec().id() + " (" + settings.describeTarget() + ")";
    }

    @Override
    public void close() {
        dataSource.close();
    }
}