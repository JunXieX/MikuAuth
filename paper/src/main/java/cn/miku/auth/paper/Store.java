package cn.miku.auth.paper;

import java.io.File;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Locale;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * SQLite 账号库（与代理端表结构一致，可共用同一个库）。
 *
 * <p>表：{@code miku_players}（uuid 主键 + nickname_lower 唯一）、{@code miku_audit_log}。
 *
 * <p><b>并发口径</b>：整个类只有一条 JDBC 连接，而调用方来自三个地方 ——
 * 配置阶段的虚拟线程（每人一条）、主线程（对话框点击回调）、异步调度器（审计清理）。
 * JDBC 连接对象本身不是线程安全的，并发 {@code prepareStatement} 会直接抛
 * "The connection is closed" / {@code SQLITE_BUSY} 之类的异常；而这里的读方法又是
 * fail-closed 的（读失败按"没有账号"处理），一旦发生就会把老玩家判成未注册、
 * 弹注册框、再被唯一约束顶回"已注册"，形成无解循环。
 * 因此<b>所有</b>公开方法都用同一把锁串行化：SQLite 本来就是单写者，排队没有额外代价。
 */
public final class Store implements AutoCloseable {

    /** 注册结果。 */
    public enum Result {
        OK, DUPLICATE, IP_LIMIT, ERROR
    }

    /** 账号快照。 */
    public record Account(String nickname, String nicknameLower, String passwordHash) {
        public boolean hasPassword() {
            return passwordHash != null && !passwordHash.isEmpty();
        }
    }

    private final Connection connection;
    private final Logger logger;

    /**
     * 打开账号库。
     *
     * <p>两种后端：{@code sqlite}（单文件、开箱即用）与 {@code mariadb}/{@code mysql}
     * （共用同一套 SQL，只有建表语句的列类型与自增写法不同）。
     * 表结构与代理端一致，因此两端可以指向同一个库。
     */
    public Store(File dataFolder, PaperConfig config, Logger logger) throws SQLException {
        this.logger = logger;
        boolean network = "mariadb".equals(config.databaseType()) || "mysql".equals(config.databaseType());
        if (!network) {
            if (!dataFolder.exists() && !dataFolder.mkdirs()) {
                throw new SQLException("无法创建数据目录: " + dataFolder);
            }
            this.connection = DriverManager.getConnection(
                    "jdbc:sqlite:" + new File(dataFolder, config.databaseFile()).getAbsolutePath());
            try (Statement statement = connection.createStatement()) {
                statement.execute("PRAGMA journal_mode=WAL");
                statement.execute("PRAGMA synchronous=NORMAL");
                statement.execute("PRAGMA busy_timeout=5000");
                statement.executeUpdate(SQLITE_PLAYERS);
                statement.executeUpdate(SQLITE_AUDIT);
            }
            return;
        }
        String prefix = "mysql".equals(config.databaseType()) ? "jdbc:mysql://" : "jdbc:mariadb://";
        String url = prefix + config.mariaDbHost() + ":" + config.mariaDbPort() + "/"
                + config.mariaDbDatabase() + "?sslMode=disable&connectTimeout=5000&socketTimeout=30000";
        this.connection = DriverManager.getConnection(url,
                config.mariaDbUsername(), config.mariaDbPassword());
        try (Statement statement = connection.createStatement()) {
            statement.executeUpdate(NETWORK_PLAYERS);
            statement.executeUpdate(NETWORK_AUDIT);
        }
    }

    private static final String SQLITE_PLAYERS = """
            CREATE TABLE IF NOT EXISTS miku_players (
                uuid            TEXT PRIMARY KEY,
                nickname_lower  TEXT NOT NULL UNIQUE,
                display_name    TEXT NOT NULL,
                password_hash   TEXT,
                auth_type       TEXT NOT NULL,
                register_ip     TEXT,
                register_time   INTEGER,
                last_login_ip   TEXT,
                last_login_time INTEGER
            )""";
    private static final String SQLITE_AUDIT = """
            CREATE TABLE IF NOT EXISTS miku_audit_log (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                nickname       TEXT NOT NULL,
                nickname_lower TEXT NOT NULL,
                uuid           TEXT,
                ip             TEXT,
                action         TEXT NOT NULL,
                detail         TEXT,
                created_at     INTEGER NOT NULL
            )""";
    private static final String NETWORK_PLAYERS = """
            CREATE TABLE IF NOT EXISTS miku_players (
                uuid            CHAR(36)    NOT NULL,
                nickname_lower  VARCHAR(16) NOT NULL,
                display_name    VARCHAR(16) NOT NULL,
                password_hash   VARCHAR(255) NULL,
                auth_type       VARCHAR(16) NOT NULL,
                register_ip     VARCHAR(45) NULL,
                register_time   BIGINT      NULL,
                last_login_ip   VARCHAR(45) NULL,
                last_login_time BIGINT      NULL,
                PRIMARY KEY (uuid),
                UNIQUE KEY uk_players_nickname (nickname_lower)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""";
    private static final String NETWORK_AUDIT = """
            CREATE TABLE IF NOT EXISTS miku_audit_log (
                id             BIGINT       NOT NULL AUTO_INCREMENT,
                nickname       VARCHAR(16)  NOT NULL,
                nickname_lower VARCHAR(16)  NOT NULL,
                uuid           CHAR(36)     NULL,
                ip             VARCHAR(45)  NULL,
                action         VARCHAR(32)  NOT NULL,
                detail         VARCHAR(255) NULL,
                created_at     BIGINT       NOT NULL,
                PRIMARY KEY (id),
                KEY idx_audit_nickname (nickname_lower, created_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""";

    private static String lower(String nickname) {
        return nickname.toLowerCase(Locale.ROOT);
    }

    /** 按昵称查账号；不存在返回 null。 */
    public synchronized Account find(String nickname) {
        try (PreparedStatement ps = connection.prepareStatement(
                "SELECT display_name, nickname_lower, password_hash FROM miku_players WHERE nickname_lower = ?")) {
            ps.setString(1, lower(nickname));
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) {
                    return null;
                }
                return new Account(rs.getString(1), rs.getString(2), rs.getString(3));
            }
        } catch (SQLException e) {
            // 读失败不能静默当成"没注册"：那会让老玩家被推去注册，撞上唯一约束后彻底进不来
            logger.log(Level.WARNING, "[数据库] 查询账号失败: " + nickname, e);
            return null;
        }
    }

    /** 某 IP 名下已有的离线账号数（注册 IP 与最近登录 IP 去重）。 */
    public synchronized int countByIp(String ip) {
        try (PreparedStatement ps = connection.prepareStatement("""
                SELECT COUNT(*) FROM (
                    SELECT nickname_lower FROM miku_players WHERE register_ip = ?
                    UNION
                    SELECT nickname_lower FROM miku_players WHERE last_login_ip = ?
                )""")) {
            ps.setString(1, ip);
            ps.setString(2, ip);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getInt(1) : 0;
            }
        } catch (SQLException e) {
            logger.log(Level.WARNING, "[数据库] 统计 IP 账号数失败: " + ip, e);
            return Integer.MAX_VALUE; // 统计失败时按"已满"处理，避免绕过配额
        }
    }

    /** 注册；唯一约束冲突返回 {@link Result#DUPLICATE}，与真正的故障区分开。 */
    public synchronized Result register(UUID uuid, String nickname, String passwordHash, String ip, int maxAccounts) {
        if (maxAccounts > 0 && countByIp(ip) >= maxAccounts) {
            return Result.IP_LIMIT;
        }
        long now = System.currentTimeMillis();
        try (PreparedStatement ps = connection.prepareStatement("""
                INSERT INTO miku_players
                    (uuid, nickname_lower, display_name, password_hash, auth_type,
                     register_ip, register_time, last_login_ip, last_login_time)
                VALUES (?, ?, ?, ?, 'OFFLINE', ?, ?, ?, ?)""")) {
            ps.setString(1, uuid.toString());
            ps.setString(2, lower(nickname));
            ps.setString(3, nickname);
            ps.setString(4, passwordHash);
            ps.setString(5, ip);
            ps.setLong(6, now);
            ps.setString(7, ip);
            ps.setLong(8, now);
            ps.executeUpdate();
            return Result.OK;
        } catch (SQLException e) {
            String message = e.getMessage() == null ? "" : e.getMessage().toLowerCase(Locale.ROOT);
            if (message.contains("unique") || message.contains("constraint") || message.contains("duplicate")) {
                return Result.DUPLICATE;
            }
            logger.log(Level.WARNING, "[数据库] 写入账号失败: " + nickname, e);
            return Result.ERROR;
        }
    }

    /** 更新密码哈希。 */
    public synchronized boolean updatePassword(String nickname, String passwordHash) {
        try (PreparedStatement ps = connection.prepareStatement(
                "UPDATE miku_players SET password_hash = ? WHERE nickname_lower = ?")) {
            ps.setString(1, passwordHash);
            ps.setString(2, lower(nickname));
            return ps.executeUpdate() > 0;
        } catch (SQLException e) {
            logger.log(Level.WARNING, "[数据库] 更新密码失败: " + nickname, e);
            return false;
        }
    }

    /** 该账号最近一次登录 IP；没有记录返回 null。 */
    public synchronized String lastIp(String nicknameLower) {
        try (PreparedStatement ps = connection.prepareStatement(
                "SELECT last_login_ip FROM miku_players WHERE nickname_lower = ?")) {
            ps.setString(1, nicknameLower);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getString(1) : null;
            }
        } catch (SQLException e) {
            logger.log(Level.WARNING, "[数据库] 查询最近登录 IP 失败: " + nicknameLower, e);
            return null;
        }
    }

    /** 最近若干条审计（时间倒序，已格式化为单行文本）。 */
    public synchronized java.util.List<String> recentAudit(String nickname, int limit) {
        java.util.List<String> lines = new java.util.ArrayList<>();
        try (PreparedStatement ps = connection.prepareStatement(
                "SELECT action, detail, ip, created_at FROM miku_audit_log "
                        + "WHERE nickname_lower = ? ORDER BY id DESC LIMIT ?")) {
            ps.setString(1, lower(nickname));
            ps.setInt(2, Math.max(1, limit));
            try (ResultSet rs = ps.executeQuery()) {
                java.text.SimpleDateFormat format = new java.text.SimpleDateFormat("MM-dd HH:mm:ss");
                while (rs.next()) {
                    lines.add(" - " + format.format(new java.util.Date(rs.getLong(4)))
                            + " | " + rs.getString(1)
                            + " | " + (rs.getString(3) == null ? "-" : rs.getString(3))
                            + " | " + (rs.getString(2) == null ? "-" : rs.getString(2)));
                }
            }
        } catch (SQLException e) {
            // 查询失败按"没有记录"处理，由命令层给出提示
            logger.log(Level.WARNING, "[数据库] 查询审计失败: " + nickname, e);
        }
        return lines;
    }

    /** 记录最近登录 IP/时间。 */
    public synchronized void finishLogin(String nickname, String ip) {
        try (PreparedStatement ps = connection.prepareStatement(
                "UPDATE miku_players SET last_login_ip = ?, last_login_time = ? WHERE nickname_lower = ?")) {
            ps.setString(1, ip);
            ps.setLong(2, System.currentTimeMillis());
            ps.setString(3, lower(nickname));
            ps.executeUpdate();
        } catch (SQLException e) {
            // 最近登录只是排查线索，写失败不影响登录结果
            logger.log(Level.FINE, "[数据库] 更新最近登录失败: " + nickname, e);
        }
    }

    /** 追加审计（失败只吞掉：审计是旁路，不能成为新的故障点）。 */
    public synchronized void audit(String nickname, UUID uuid, String ip, String action, String detail) {
        try (PreparedStatement ps = connection.prepareStatement("""
                INSERT INTO miku_audit_log (nickname, nickname_lower, uuid, ip, action, detail, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)""")) {
            ps.setString(1, nickname);
            ps.setString(2, lower(nickname));
            ps.setString(3, uuid == null ? null : uuid.toString());
            ps.setString(4, ip);
            ps.setString(5, action);
            ps.setString(6, detail);
            ps.setLong(7, System.currentTimeMillis());
            ps.executeUpdate();
        } catch (SQLException e) {
            logger.log(Level.FINE, "[数据库] 写审计失败: " + nickname, e);
        }
    }

    /** 删除早于 cutoff 的审计记录（按保留天数定期清理）。 */
    public synchronized void purgeAudit(long cutoffMillis) {
        try (PreparedStatement ps = connection.prepareStatement(
                "DELETE FROM miku_audit_log WHERE created_at < ?")) {
            ps.setLong(1, cutoffMillis);
            ps.executeUpdate();
        } catch (SQLException e) {
            logger.log(Level.FINE, "[数据库] 清理审计失败", e);
        }
    }

    @Override
    public synchronized void close() {
        try {
            connection.close();
        } catch (SQLException e) {
            logger.log(Level.FINE, "[数据库] 关闭连接失败", e);
        }
    }
}
