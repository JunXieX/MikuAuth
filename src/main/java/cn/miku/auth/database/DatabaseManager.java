package cn.miku.auth.database;

import cn.miku.auth.audit.AuditAction;
import cn.miku.auth.audit.AuditEntry;
import cn.miku.auth.audit.AuditRepository;
import cn.miku.auth.config.MikuConfig;
import cn.miku.auth.util.UuidUtil;

import java.io.IOException;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;
import org.slf4j.Logger;

/**
 * 数据层门面：对外只暴露方言无关的异步操作，内部委托给 {@link SqlBackend}。
 *
 * <p>支持两种后端（config.yml 的 {@code database.type}）：
 * <ul>
 *   <li><b>sqlite</b>（默认）：单文件、单连接、单线程串行执行，零外部依赖；</li>
 *   <li><b>mariadb</b>：网络数据库 + HikariCP 连接池，供多代理实例共享账号库。</li>
 * </ul>
 *
 * <p>所有操作都提交到内部执行器执行，绝不阻塞 Velocity/Netty 线程；
 * 结果统一以 {@link CompletableFuture} 返回，由调用方编排。
 *
 * <p><b>异常语义</b>：写操作区分"业务性失败"（昵称重复）与"真正的故障"（磁盘/网络/锁），
 * 前者返回 {@link RegisterResult#DUPLICATE}，后者返回 {@link RegisterResult#ERROR}，
 * 避免把数据库故障伪装成"昵称已被注册"误导玩家与管理员。
 */
public final class DatabaseManager implements AuthRepository, AuditRepository, AutoCloseable {

    /** 注册结果。 */
    public enum RegisterResult {
        /** 写入成功。 */
        OK,
        /** 昵称已存在（主键冲突）。 */
        DUPLICATE,
        /** 数据库故障（磁盘满、连接中断、库被锁等）。 */
        ERROR
    }

    private final Logger logger;
    private final ExecutorService executor;
    private final SqlBackend backend;

    /**
     * 数据库任务队列上限。
     *
     * <p>取 512 而非无界：正常负载下队列几乎为空，洪泛时宁可让个别任务快速失败
     * （调用方会收到异常并记 WARN），也不允许内存无限增长。
     */
    private static final int QUEUE_CAPACITY = 512;

    /** 会话记录快照（同 IP 免密）。 */
    public record Session(String nicknameLower, String ip, long expiresAt) {
    }

    /**
     * 迁移写入请求（批量导入用）。
     *
     * @param passwordHash 可为 null（源库算法不受支持时）
     */
    public record ImportRequest(UUID uuid, String nickname, String passwordHash, String authType,
                                String ip, long registerTime, long lastLoginTime) {
    }

    public DatabaseManager(Path dataDirectory, MikuConfig config, Logger logger) throws SQLException, IOException {
        this.logger = logger;
        this.backend = createBackend(dataDirectory, config, logger);
        // 有界队列：与密码线程池（有界 + AbortPolicy）保持一致的设计。
        // SQLite 后端只有 1 个工作线程，若队列无界，一旦提交速率持续高于处理能力
        // （例如暴破时每条失败都写审计 + 每次连接查库），任务会无限堆积导致内存缓涨。
        // 队列满时直接拒绝，由 supply() 让调用方的 future 立即失败，而不是无限排队。
        this.executor = new ThreadPoolExecutor(
                backend.workerThreads(), backend.workerThreads(),
                0L, TimeUnit.MILLISECONDS,
                new LinkedBlockingQueue<>(QUEUE_CAPACITY),
                runnable -> {
                    Thread thread = new Thread(runnable, "MikuAuth-Database");
                    thread.setDaemon(true);
                    return thread;
                },
                new ThreadPoolExecutor.AbortPolicy());
        try {
            initialize();
        } catch (SQLException e) {
            // 初始化失败必须回收已创建的资源，否则插件停用后连接池/线程会一直挂着
            backend.close();
            executor.shutdownNow();
            throw e;
        }
    }

    /** 按配置选择后端；配置写错时回退 SQLite 并给出告警。 */
    private static SqlBackend createBackend(Path dataDirectory, MikuConfig config, Logger logger)
            throws SQLException, IOException {
        String type = config.databaseType();
        if ("mariadb".equals(type) || "mysql".equals(type)) {
            return new MariaDbBackend(new MariaDbBackend.Settings(
                    config.mariaDbHost(), config.mariaDbPort(), config.mariaDbDatabase(),
                    config.mariaDbUsername(), config.mariaDbPassword(), config.mariaDbSslMode(),
                    config.mariaDbPoolSize(), config.mariaDbConnectionTimeoutMillis()), logger);
        }
        if (!"sqlite".equals(type)) {
            logger.warn("[数据库] 未知的 database.type '{}'，已回退 SQLite（可选值：sqlite / mariadb）", type);
        }
        return new SqliteBackend(dataDirectory, config.databaseFile());
    }

    /** 建表并设置后端参数。 */
    private void initialize() throws SQLException {
        Connection connection = backend.borrow();
        try {
            // 老库升级必须在建表之前：CREATE TABLE IF NOT EXISTS 不会修正已存在的旧结构
            migratePlayersToUuidSchema(connection);
            try (Statement statement = connection.createStatement()) {
                for (String ddl : backend.schemaStatements()) {
                    statement.executeUpdate(ddl);
                }
            }
        } finally {
            backend.release(connection);
        }
        if (logger != null) {
            logger.info("[数据库] 已就绪：{}", backend.describe());
        }
    }

    // ---------------------------------------------------------------------
    // 账号操作
    // ---------------------------------------------------------------------

    /** 按昵称查找账号（大小写不敏感）。 */
    public CompletableFuture<Optional<StoredPlayer>> findPlayer(String nickname) {
        return supply(connection -> {
            try (PreparedStatement ps = connection.prepareStatement(
                    "SELECT * FROM miku_players WHERE nickname_lower = ?")) {
                ps.setString(1, MikuConfig.normalize(nickname));
                try (ResultSet rs = ps.executeQuery()) {
                    return rs.next() ? Optional.of(readPlayer(rs)) : Optional.<StoredPlayer>empty();
                }
            }
        });
    }

    /**
     * 按 UUID 查找账号 —— 账号的真正身份键。
     *
     * <p>用于"正版玩家改名"的识别：新昵称查不到记录时，用 Mojang UUID 反查，
     * 命中即说明该玩家只是改了名，账号数据应迁移到新昵称、旧昵称随之释放。
     */
    public CompletableFuture<Optional<StoredPlayer>> findPlayerByUuid(UUID uuid) {
        return supply(connection -> {
            try (PreparedStatement ps = connection.prepareStatement(
                    "SELECT * FROM miku_players WHERE uuid = ?")) {
                ps.setString(1, UuidUtil.format(uuid));
                try (ResultSet rs = ps.executeQuery()) {
                    return rs.next() ? Optional.of(readPlayer(rs)) : Optional.<StoredPlayer>empty();
                }
            }
        });
    }

    /**
     * 注册新账号。
     *
     * @param uuid 账号身份键：正版传 Mojang UUID，离线传 {@link UuidUtil#offlineUuid(String)}
     * @return 昵称或 UUID 已存在时返回 {@link RegisterResult#DUPLICATE}，
     *         数据库故障返回 {@link RegisterResult#ERROR}
     */
    public CompletableFuture<RegisterResult> register(UUID uuid, String nickname, String passwordHash,
                                                      String authType, String ip) {
        return supply(connection -> {
            try (PreparedStatement ps = connection.prepareStatement("""
                    INSERT INTO miku_players
                        (uuid, nickname_lower, display_name, password_hash, auth_type,
                         register_ip, register_time, last_login_ip, last_login_time)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""")) {
                long now = System.currentTimeMillis();
                ps.setString(1, UuidUtil.format(uuid));
                ps.setString(2, MikuConfig.normalize(nickname));
                ps.setString(3, nickname);
                ps.setString(4, passwordHash);
                ps.setString(5, authType);
                ps.setString(6, ip);
                ps.setLong(7, now);
                ps.setString(8, ip);
                ps.setLong(9, now);
                ps.executeUpdate();
                return RegisterResult.OK;
            } catch (SQLException e) {
                if (isUniqueViolation(e)) {
                    return RegisterResult.DUPLICATE;
                }
                logger.error("[数据库] 注册 {} 失败: {}", nickname, e.getMessage());
                return RegisterResult.ERROR;
            }
        });
    }

    /**
     * 把某 UUID 的账号迁移到新昵称（正版玩家改名后的自动迁移）。
     *
     * <p>只改昵称，密码、注册信息、登录统计全部保留 —— 这正是"用 UUID 保存数据"的意义：
     * 账号跟着人走，而不是跟着名字走。旧昵称从唯一索引中消失，随即被释放。
     *
     * @return true = 迁移成功；false = 新昵称已被别的账号占用（按冲突处理，不迁移）
     */
    public CompletableFuture<Boolean> renameAccount(UUID uuid, String newNickname) {
        return supply(connection -> {
            try (PreparedStatement ps = connection.prepareStatement(
                    "UPDATE miku_players SET nickname_lower = ?, display_name = ? WHERE uuid = ?")) {
                ps.setString(1, MikuConfig.normalize(newNickname));
                ps.setString(2, newNickname);
                ps.setString(3, UuidUtil.format(uuid));
                return ps.executeUpdate() > 0;
            } catch (SQLException e) {
                if (isUniqueViolation(e)) {
                    // 新昵称已被占用：保持原样，交由上层按"昵称冲突"处理
                    return false;
                }
                throw e;
            }
        });
    }

    /** 判断是否为唯一约束冲突（SQLite 与 MariaDB 的报错文案不同）。 */
    private static boolean isUniqueViolation(SQLException e) {
        String message = e.getMessage();
        if (message == null) {
            return false;
        }
        String lower = message.toLowerCase(Locale.ROOT);
        return lower.contains("unique constraint failed")   // SQLite
                || lower.contains("duplicate entry")        // MariaDB
                || lower.contains("duplicate key");
    }

    /**
     * 删除"陈旧的正版记录"，把被它占用的昵称释放出来。
     *
     * <p>这是"正版玩家改名后自动清理旧 ID"的落地点：调用方必须先确认该昵称
     * <b>已不再属于记录里的正版 UUID</b>（权威源判定离线 / 镜像给出的历史 UUID 与记录一致）。
     *
     * <p><b>安全约束</b>：只删 {@code auth_type = PREMIUM} 且<b>没有密码</b>的记录 ——
     * 带密码的记录（只能由管理员 setpassword 产生）不自动删除，避免误删可登录的凭据，
     * 那种情况仍由 {@code /mikuauth unbind} 手工处理。
     *
     * @param expectedUuid 已知的历史 UUID；为 null 时不做 UUID 比对（权威源已明确该昵称不存在）
     * @return true = 确实删除了一条陈旧记录
     */
    public CompletableFuture<Boolean> releaseStaleAccount(String nickname, UUID expectedUuid) {
        return supply(connection -> {
            String sql = "DELETE FROM miku_players WHERE nickname_lower = ? AND auth_type = ?"
                    + " AND (password_hash IS NULL OR password_hash = '')"
                    + (expectedUuid != null ? " AND uuid = ?" : "");
            try (PreparedStatement ps = connection.prepareStatement(sql)) {
                ps.setString(1, MikuConfig.normalize(nickname));
                ps.setString(2, StoredPlayer.TYPE_PREMIUM);
                if (expectedUuid != null) {
                    ps.setString(3, UuidUtil.format(expectedUuid));
                }
                return ps.executeUpdate() > 0;
            }
        });
    }

    /**
     * 更新密码哈希。
     * 同时用于玩家自助改密（{@code /changepassword}）与管理员重置（{@code /mikuauth setpassword}）。
     *
     * @return true = 账号存在且已更新
     */
    public CompletableFuture<Boolean> updatePassword(String nickname, String passwordHash) {
        return supply(connection -> {
            try (PreparedStatement ps = connection.prepareStatement(
                    "UPDATE miku_players SET password_hash = ? WHERE nickname_lower = ?")) {
                ps.setString(1, passwordHash);
                ps.setString(2, MikuConfig.normalize(nickname));
                return ps.executeUpdate() > 0;
            }
        });
    }

    /** 删除密码（账号回到未设置密码状态）；成功返回 true。 */
    public CompletableFuture<Boolean> deletePassword(String nickname) {
        return supply(connection -> {
            try (PreparedStatement ps = connection.prepareStatement(
                    "UPDATE miku_players SET password_hash = NULL WHERE nickname_lower = ?")) {
                ps.setString(1, MikuConfig.normalize(nickname));
                return ps.executeUpdate() > 0;
            }
        });
    }

    /**
     * 清除正版绑定：把账号降级为普通离线账号（保留密码）。
     *
     * <p>身份键也要一并换成离线 UUID —— 解绑后账号按离线账号对待，
     * 若仍保留 Mojang UUID，玩家离线登录时算出的离线 UUID 与库中不一致，
     * 账号会变成"孤儿记录"（昵称被占、却谁也进不来）。
     *
     * <p>改名场景现在已由自动迁移处理，本方法保留给管理员手工干预。
     *
     * @return true = 确实清除了绑定；false = 账号不存在或本来就没有绑定
     */
    public CompletableFuture<Boolean> clearPremiumBinding(String nickname) {
        return supply(connection -> {
            String normalized = MikuConfig.normalize(nickname);
            String displayName;
            try (PreparedStatement ps = connection.prepareStatement(
                    "SELECT display_name FROM miku_players WHERE nickname_lower = ? AND auth_type = ?")) {
                ps.setString(1, normalized);
                ps.setString(2, StoredPlayer.TYPE_PREMIUM);
                try (ResultSet rs = ps.executeQuery()) {
                    if (!rs.next()) {
                        return false;
                    }
                    displayName = rs.getString(1);
                }
            }
            try (PreparedStatement ps = connection.prepareStatement(
                    "UPDATE miku_players SET auth_type = ?, uuid = ? WHERE nickname_lower = ? AND auth_type = ?")) {
                ps.setString(1, StoredPlayer.TYPE_OFFLINE);
                ps.setString(2, UuidUtil.format(UuidUtil.offlineUuid(displayName)));
                ps.setString(3, normalized);
                ps.setString(4, StoredPlayer.TYPE_PREMIUM);
                return ps.executeUpdate() > 0;
            }
        });
    }

    /** 记录一次成功登录（更新最近登录 IP 与时间）。 */
    public CompletableFuture<Void> recordLogin(String nickname, String ip) {
        return supply(connection -> {
            try (PreparedStatement ps = connection.prepareStatement(
                    "UPDATE miku_players SET last_login_ip = ?, last_login_time = ? WHERE nickname_lower = ?")) {
                ps.setString(1, ip);
                ps.setLong(2, System.currentTimeMillis());
                ps.setString(3, MikuConfig.normalize(nickname));
                ps.executeUpdate();
            }
            return null;
        });
    }

    /**
     * 统计某 IP 名下的<b>离线</b>账号数量（注册 IP 与最近登录 IP 任一匹配即计入，去重）。
     *
     * <p>口径说明：正版账号（由正版玩家自动登记）不计入配额——它们的创建不由玩家
     * 自由发起，把它们算进来会让"同 IP 下 3 个正版玩家"直接堵死第 4 个离线账号的注册。
     */
    public CompletableFuture<Integer> countAccountsByIp(String ip) {
        return supply(connection -> {
            try (PreparedStatement ps = connection.prepareStatement("""
                    SELECT COUNT(DISTINCT nickname_lower) FROM miku_players
                    WHERE (register_ip = ? OR last_login_ip = ?) AND auth_type <> ?""")) {
                ps.setString(1, ip);
                ps.setString(2, ip);
                ps.setString(3, StoredPlayer.TYPE_PREMIUM);
                try (ResultSet rs = ps.executeQuery()) {
                    return rs.next() ? rs.getInt(1) : 0;
                }
            }
        });
    }

    /** 列出某 IP 名下的所有账号（管理查询用，含正版账号）。 */
    public CompletableFuture<List<StoredPlayer>> findAccountsByIp(String ip) {
        return supply(connection -> {
            List<StoredPlayer> players = new ArrayList<>();
            try (PreparedStatement ps = connection.prepareStatement("""
                    SELECT * FROM miku_players
                    WHERE register_ip = ? OR last_login_ip = ?
                    ORDER BY register_time DESC""")) {
                ps.setString(1, ip);
                ps.setString(2, ip);
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        players.add(readPlayer(rs));
                    }
                }
            }
            return players;
        });
    }

    // ---------------------------------------------------------------------
    // 会话操作（同 IP 免密）
    // ---------------------------------------------------------------------

    /** 写入/刷新会话。 */
    public CompletableFuture<Void> saveSession(String nickname, String ip, long expiresAtMillis) {
        return supply(connection -> {
            try (PreparedStatement ps = connection.prepareStatement(backend.upsertSessionSql())) {
                ps.setString(1, MikuConfig.normalize(nickname));
                ps.setString(2, ip);
                ps.setLong(3, expiresAtMillis);
                ps.executeUpdate();
            }
            return null;
        });
    }

    /** 查询有效会话；已过期的不返回（由清理任务删除）。 */
    public CompletableFuture<Optional<Session>> findSession(String nickname) {
        return supply(connection -> {
            try (PreparedStatement ps = connection.prepareStatement(
                    "SELECT nickname_lower, ip, expires_at FROM miku_sessions "
                            + "WHERE nickname_lower = ? AND expires_at > ?")) {
                ps.setString(1, MikuConfig.normalize(nickname));
                ps.setLong(2, System.currentTimeMillis());
                try (ResultSet rs = ps.executeQuery()) {
                    return rs.next()
                            ? Optional.of(new Session(rs.getString(1), rs.getString(2), rs.getLong(3)))
                            : Optional.<Session>empty();
                }
            }
        });
    }

    /** 删除会话（改密码 / 重置密码后让旧会话立即失效）。 */
    public CompletableFuture<Void> clearSession(String nickname) {        return supply(connection -> {
            try (PreparedStatement ps = connection.prepareStatement(
                    "DELETE FROM miku_sessions WHERE nickname_lower = ?")) {
                ps.setString(1, MikuConfig.normalize(nickname));
                ps.executeUpdate();
            }
            return null;
        });
    }

    /** 清理全部过期会话，返回删除行数。 */
    public CompletableFuture<Integer> purgeExpiredSessions() {
        return supply(connection -> {
            try (PreparedStatement ps = connection.prepareStatement(
                    "DELETE FROM miku_sessions WHERE expires_at <= ?")) {
                ps.setLong(1, System.currentTimeMillis());
                return ps.executeUpdate();
            }
        });
    }

    // ---------------------------------------------------------------------
    // 账号表结构升级（昵称主键 → UUID 主键）
    // ---------------------------------------------------------------------

    /** 旧结构下的一行（可能没有 uuid 列）。 */
    private record LegacyRow(String nicknameLower, String displayName, String passwordHash, String authType,
                             String premiumUuid, String registerIp, long registerTime,
                             String lastLoginIp, long lastLoginTime) {

        boolean hasPassword() {
            return passwordHash != null && !passwordHash.isEmpty();
        }
    }

    /**
     * 老库升级：把 {@code miku_players} 从"昵称主键"迁移到"UUID 主键"。
     *
     * <p>升级内容：
     * <ol>
     *   <li>为每行计算身份 UUID：正版账号取原 {@code premium_uuid}，
     *       离线账号取由昵称推导的离线 UUID；</li>
     *   <li><b>按 UUID 去重</b> —— 旧结构下同一正版玩家改名后会被登记成新昵称的新记录，
     *       于是同一 UUID 留下多条记录，旧那条就成了"死昵称"。
     *       这里保留"有密码的 / 最近使用的"那条，其余删除并释放其昵称；</li>
     *   <li>整表重建为 {@code uuid} 主键 + {@code nickname_lower} 唯一索引。</li>
     * </ol>
     *
     * <p><b>安全性</b>：迁移在事务中执行；只有在迁移表行数与预期一致时才替换正式表
     * （MariaDB 用单条 {@code RENAME TABLE} 原子换名）；任何异常都保留原表不动并向上抛出，
     * 由插件停用并给出明确报错，绝不带着半迁移状态运行。
     */
    private void migratePlayersToUuidSchema(Connection connection) throws SQLException {
        if (!tableExists(connection, "miku_players") || tableHasColumn(connection, "miku_players", "uuid")) {
            return; // 全新安装，或已经是新结构
        }
        logger.warn("[数据库] 检测到旧版账号表（昵称主键），开始升级为 UUID 主键…");

        List<LegacyRow> legacy = new ArrayList<>();
        try (Statement statement = connection.createStatement();
             ResultSet rs = statement.executeQuery("SELECT * FROM miku_players")) {
            while (rs.next()) {
                legacy.add(new LegacyRow(
                        rs.getString("nickname_lower"), rs.getString("display_name"),
                        rs.getString("password_hash"), rs.getString("auth_type"),
                        rs.getString("premium_uuid"), rs.getString("register_ip"),
                        rs.getLong("register_time"), rs.getString("last_login_ip"),
                        rs.getLong("last_login_time")));
            }
        }

        Map<String, LegacyRow> kept = new LinkedHashMap<>();
        List<String> released = new ArrayList<>();
        for (LegacyRow row : legacy) {
            UUID premium = UuidUtil.parse(row.premiumUuid());
            UUID uuid = premium != null ? premium : UuidUtil.offlineUuid(row.displayName());
            LegacyRow previous = kept.get(uuid.toString());
            if (previous == null) {
                kept.put(uuid.toString(), row);
            } else if (preferOver(row, previous)) {
                kept.put(uuid.toString(), row);
                released.add(previous.nicknameLower());
            } else {
                released.add(row.nicknameLower());
            }
        }

        boolean originalAutoCommit = connection.getAutoCommit();
        try {
            connection.setAutoCommit(false);
            String migrating = requireSafeIdentifier("miku_players_migrating");
            try (Statement statement = connection.createStatement()) {
                statement.executeUpdate("DROP TABLE IF EXISTS " + migrating);
                statement.executeUpdate(backend.playersDdl(migrating));
            }
            try (PreparedStatement ps = connection.prepareStatement(
                    "INSERT INTO " + migrating
                            + " (uuid, nickname_lower, display_name, password_hash, auth_type,"
                            + " register_ip, register_time, last_login_ip, last_login_time)"
                            + " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")) {
                for (Map.Entry<String, LegacyRow> entry : kept.entrySet()) {
                    LegacyRow row = entry.getValue();
                    ps.setString(1, entry.getKey());
                    ps.setString(2, row.nicknameLower());
                    ps.setString(3, row.displayName());
                    ps.setString(4, row.passwordHash());
                    ps.setString(5, row.authType());
                    ps.setString(6, row.registerIp());
                    ps.setLong(7, row.registerTime());
                    ps.setString(8, row.lastLoginIp());
                    ps.setLong(9, row.lastLoginTime());
                    ps.addBatch();
                }
                ps.executeBatch();
            }

            int migrated = countRows(connection, migrating);
            if (migrated != kept.size()) {
                connection.rollback();
                throw new SQLException("账号表升级校验失败：期望 " + kept.size()
                        + " 行，实际 " + migrated + " 行，已放弃升级（原表未改动）");
            }
            backend.swapPlayersTable(connection, migrating);
            connection.commit();
            logger.warn("[数据库] 账号表已升级为 UUID 主键，迁移 {} 条记录", migrated);
            if (!released.isEmpty()) {
                logger.warn("[数据库] 自动清理了 {} 条同一 UUID 的重复记录（改名遗留），释放昵称: {}",
                        released.size(), String.join(", ", released));
            }
        } catch (SQLException e) {
            try {
                connection.rollback();
            } catch (SQLException ignored) {
                // 回滚失败时保留原始异常更有价值
            }
            throw e;
        } finally {
            try {
                connection.setAutoCommit(originalAutoCommit);
            } catch (SQLException ignored) {
                // 恢复失败不影响迁移结果
            }
        }
    }

    /** 去重时优先保留哪一条：先看有没有密码（别把密码丢了），再看最近使用时间。 */
    private static boolean preferOver(LegacyRow candidate, LegacyRow current) {
        if (candidate.hasPassword() != current.hasPassword()) {
            return candidate.hasPassword();
        }
        return candidate.lastLoginTime() > current.lastLoginTime();
    }

    /**
     * SQL 标识符护栏：表名与列名无法用占位符参数化，只能拼接，
     * 因此这里强制校验字符集，防止将来重构时把外部输入（配置、命令参数）
     * 接到拼接位置而引入注入。
     *
     * <p>本项目的所有标识符均为小写字母/数字/下划线，校验不会误伤。
     */
    private static String requireSafeIdentifier(String identifier) {
        if (identifier == null || !identifier.matches("[a-z0-9_]{1,64}")) {
            throw new IllegalArgumentException("非法的 SQL 标识符: " + identifier);
        }
        return identifier;
    }

    /** 表是否存在（用零行查询探测，避免依赖各驱动的元数据大小写规则）。 */
    private static boolean tableExists(Connection connection, String table) {
        try (Statement statement = connection.createStatement()) {
            statement.executeQuery("SELECT 1 FROM " + requireSafeIdentifier(table) + " WHERE 1=0").close();
            return true;
        } catch (SQLException e) {
            return false;
        }
    }

    /** 表是否有某列（同上，零行查询探测）。 */
    private static boolean tableHasColumn(Connection connection, String table, String column) {
        try (Statement statement = connection.createStatement()) {
            statement.executeQuery("SELECT " + requireSafeIdentifier(column)
                    + " FROM " + requireSafeIdentifier(table) + " WHERE 1=0").close();
            return true;
        } catch (SQLException e) {
            return false;
        }
    }

    private static int countRows(Connection connection, String table) throws SQLException {
        try (Statement statement = connection.createStatement();
             ResultSet rs = statement.executeQuery(
                     "SELECT COUNT(*) FROM " + requireSafeIdentifier(table))) {
            return rs.next() ? rs.getInt(1) : 0;
        }
    }

    // ---------------------------------------------------------------------
    // 内部工具
    // ---------------------------------------------------------------------

    private static StoredPlayer readPlayer(ResultSet rs) throws SQLException {
        return new StoredPlayer(
                UuidUtil.parse(rs.getString("uuid")),
                rs.getString("display_name"),
                rs.getString("nickname_lower"),
                rs.getString("password_hash"),
                rs.getString("auth_type"),
                rs.getString("register_ip"),
                rs.getLong("register_time"),
                rs.getString("last_login_ip"),
                rs.getLong("last_login_time"));
    }

    // ---------------------------------------------------------------------
    // 审计日志
    // ---------------------------------------------------------------------

    @Override
    public CompletableFuture<Void> appendAudit(AuditEntry entry) {
        return supply(connection -> {
            try (PreparedStatement ps = connection.prepareStatement("""
                    INSERT INTO miku_audit_log
                        (nickname, nickname_lower, uuid, ip, action, detail, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)""")) {
                ps.setString(1, entry.nickname());
                ps.setString(2, MikuConfig.normalize(entry.nickname()));
                ps.setString(3, entry.uuid() == null ? null : UuidUtil.format(entry.uuid()));
                ps.setString(4, entry.ip());
                ps.setString(5, entry.action().name());
                ps.setString(6, entry.detail());
                ps.setLong(7, entry.createdAt());
                ps.executeUpdate();
            }
            return null;
        });
    }

    @Override
    public CompletableFuture<List<AuditEntry>> findAuditByNickname(String nickname, int limit) {
        return queryAudit("SELECT id, nickname, uuid, ip, action, detail, created_at "
                + "FROM miku_audit_log WHERE nickname_lower = ? ORDER BY id DESC LIMIT ?",
                MikuConfig.normalize(nickname), limit);
    }

    @Override
    public CompletableFuture<List<AuditEntry>> findAuditByIp(String ip, int limit) {
        return queryAudit("SELECT id, nickname, uuid, ip, action, detail, created_at "
                + "FROM miku_audit_log WHERE ip = ? ORDER BY id DESC LIMIT ?", ip, limit);
    }

    @Override
    public CompletableFuture<Integer> purgeExpiredAudit(long beforeMillis) {
        return supply(connection -> {
            try (PreparedStatement ps = connection.prepareStatement(
                    "DELETE FROM miku_audit_log WHERE created_at < ?")) {
                ps.setLong(1, beforeMillis);
                return ps.executeUpdate();
            }
        });
    }

    private CompletableFuture<List<AuditEntry>> queryAudit(String sql, String key, int limit) {
        return supply(connection -> {
            List<AuditEntry> entries = new ArrayList<>();
            try (PreparedStatement ps = connection.prepareStatement(sql)) {
                ps.setString(1, key);
                ps.setInt(2, Math.max(1, limit));
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        String uuidText = rs.getString("uuid");
                        entries.add(new AuditEntry(
                                rs.getLong("id"),
                                rs.getString("nickname"),
                                uuidText == null ? null : UuidUtil.parse(uuidText),
                                rs.getString("ip"),
                                parseAction(rs.getString("action")),
                                rs.getString("detail"),
                                rs.getLong("created_at")));
                    }
                }
            }
            return entries;
        });
    }

    /** 未知 action（例如降级后读到新版本写入的值）不应让查询整体失败。 */
    private static AuditAction parseAction(String raw) {
        try {
            return AuditAction.valueOf(raw);
        } catch (IllegalArgumentException | NullPointerException e) {
            return AuditAction.ADMIN_ACTION;
        }
    }

    // ---------------------------------------------------------------------
    // 迁移写入
    // ---------------------------------------------------------------------

    /**
     * 迁移写入：直接插入一条账号记录（保留原始密码哈希与历史时间），
     * 不经过注册流程的 IP 配额检查，也不刷新会话。
     *
     * <p>哈希按源插件原样存入——登录时由
     * {@link cn.miku.auth.security.PasswordHasher} 按格式识别校验，
     * 并在首次成功登录后自动升级为 BCrypt，因此玩家无需重置密码。
     *
     * @return true = 已插入；false = UUID 或昵称已存在（跳过，不覆盖现有账号）
     */
    public CompletableFuture<Boolean> importAccount(UUID uuid, String nickname, String passwordHash,
                                                    String authType, String ip,
                                                    long registerTime, long lastLoginTime) {
        return supply(connection -> {
            try (PreparedStatement ps = connection.prepareStatement("""
                    INSERT INTO miku_players
                        (uuid, nickname_lower, display_name, password_hash, auth_type,
                         register_ip, register_time, last_login_ip, last_login_time)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""")) {
                ps.setString(1, UuidUtil.format(uuid));
                ps.setString(2, MikuConfig.normalize(nickname));
                ps.setString(3, nickname);
                ps.setString(4, passwordHash);
                ps.setString(5, authType);
                ps.setString(6, ip);
                ps.setLong(7, registerTime > 0 ? registerTime : System.currentTimeMillis());
                ps.setString(8, ip);
                ps.setLong(9, lastLoginTime > 0 ? lastLoginTime : 0L);
                ps.executeUpdate();
                return true;
            } catch (SQLException e) {
                if (isUniqueViolation(e)) {
                    return false; // 账号已存在：跳过，绝不覆盖现有数据
                }
                throw e;
            }
        });
    }

    /**
     * 批量导入账号（迁移专用）。
     *
     * <p><b>为什么需要它</b>：逐条调用 {@link #importAccount} 会让每条记录都成为一次
     * 独立的数据库任务，而 SQLite 后端只有 1 个工作线程——迁移期间该线程被持续占满，
     * 在线玩家的登录、注册、会话查询全部排在迁移任务后面。批量写入把 N 条合并为
     * **一次任务 + 一次事务**，把对在线玩家的影响降到最低。
     *
     * <p>已存在的账号靠后端的 "忽略重复" 语法静默跳过（不覆盖现有数据），
     * 并用 {@code executeBatch()} 返回的更新计数统计实际写入条数。
     *
     * @return 实际写入的条数（因重复被跳过的、以及失败的条目不计入）
     */
    public CompletableFuture<Integer> importAccountsBatch(List<ImportRequest> batch) {
        return supply(connection -> {
            if (batch.isEmpty()) {
                return 0;
            }
            boolean originalAutoCommit = connection.getAutoCommit();
            try {
                connection.setAutoCommit(false);
                int inserted = 0;
                try (PreparedStatement ps = connection.prepareStatement(backend.insertIgnorePlayerSql())) {
                    for (ImportRequest request : batch) {
                        ps.setString(1, UuidUtil.format(request.uuid()));
                        ps.setString(2, MikuConfig.normalize(request.nickname()));
                        ps.setString(3, request.nickname());
                        ps.setString(4, request.passwordHash());
                        ps.setString(5, request.authType());
                        ps.setString(6, request.ip());
                        ps.setLong(7, request.registerTime() > 0
                                ? request.registerTime() : System.currentTimeMillis());
                        ps.setString(8, request.ip());
                        ps.setLong(9, request.lastLoginTime() > 0 ? request.lastLoginTime() : 0L);
                        ps.addBatch();
                    }
                    // INSERT IGNORE / INSERT OR IGNORE：重复行返回 0，新插入返回 1
                    for (int updated : ps.executeBatch()) {
                        if (updated > 0) {
                            inserted++;
                        }
                    }
                }
                connection.commit();
                return inserted;
            } catch (SQLException e) {
                try {
                    connection.rollback();
                } catch (SQLException rollbackFailure) {
                    logger.warn("[数据库] 批量导入回滚失败: {}", rollbackFailure.getMessage());
                }
                throw e;
            } finally {
                try {
                    connection.setAutoCommit(originalAutoCommit);
                } catch (SQLException ignored) {
                    // 连接即将归还连接池，恢复失败不影响正确性
                }
            }
        });
    }

    private <T> CompletableFuture<T> supply(SqlWork<T> work) {
        CompletableFuture<T> future = new CompletableFuture<>();
        try {
            executor.execute(() -> {
                Connection connection = null;
                try {
                    connection = backend.borrow();
                    future.complete(work.apply(connection));
                } catch (Throwable t) {
                    future.completeExceptionally(t);
                } finally {
                    backend.release(connection);
                }
            });
        } catch (RejectedExecutionException e) {
            // 插件正在关闭：让调用方的 future 立即失败，而不是永远悬挂
            future.completeExceptionally(e);
        }
        return future;
    }

    @FunctionalInterface
    private interface SqlWork<T> {
        T apply(Connection connection) throws Exception;
    }

    @Override
    public void close() {
        // 先停执行器并等待在途任务结束，再关连接/连接池：
        // 否则仍在执行的任务会踩到已关闭的连接
        executor.shutdown();
        try {
            if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                executor.shutdownNow();
                executor.awaitTermination(2, TimeUnit.SECONDS);
            }
        } catch (InterruptedException e) {
            executor.shutdownNow();
            Thread.currentThread().interrupt();
        }
        backend.close();
    }
}
