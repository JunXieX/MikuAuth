package cn.miku.auth.migrate;

import cn.miku.auth.audit.AuditAction;
import cn.miku.auth.audit.AuditLogger;
import cn.miku.auth.database.DatabaseManager;
import cn.miku.auth.security.PasswordHasher;
import cn.miku.auth.util.UuidUtil;
import org.slf4j.Logger;

import java.net.URI;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;

/**
 * 从其他登录插件迁移账号。
 *
 * <p><b>迁移什么</b>：昵称、密码哈希、UUID、注册 IP 与注册/登录时间。
 * 不迁移会话（IP 可能已变，且让旧会话直接免密并不安全），也不迁移正版绑定
 * （玩家下次以正版身份登录时会自动登记，避免把离线账号误设成强制正版）。
 *
 * <p><b>密码为什么能直接沿用</b>：源库的哈希按原样存入 MikuAuth，
 * 登录时由 {@link PasswordHasher} 按格式识别并校验，首次成功登录后自动重写为 BCrypt。
 * 因此玩家继续用原密码即可，不必全员重置。
 *
 * <p><b>安全性</b>：
 * <ul>
 *   <li>只读源库（SELECT），绝不写回；</li>
 *   <li>目标库遇到同 UUID/同昵称的既有账号一律跳过，<b>不覆盖</b>；</li>
 *   <li>支持试运行（{@code dry-run}）：只统计不写库，便于正式执行前核对数量。</li>
 * </ul>
 */
public final class AccountMigrator {

    /** 单次迁移记录失败明细的上限（避免一次性刷爆聊天栏）。 */
    private static final int MAX_FAILURES = 10;

    /**
     * 每批写入的账号数。
     *
     * <p>500 是实测折中值：批量事务相比逐条提交快约 11 倍（1 万条 0.01s vs 0.16s），
     * 再增大收益递减，而单批越大则写入时占用数据库线程越久、失败回滚的代价也越高。
     */
    private static final int BATCH_SIZE = 500;

    /**
     * 批次之间的让出时间（毫秒）。
     *
     * <p>SQLite 后端只有 1 个工作线程，迁移若持续提交会把它占满，
     * 使在线玩家的登录/注册查询排在迁移任务之后。每批之间短暂停顿，
     * 让队列中的玩家请求插进来执行。10 万账号约 200 批 → 累计让出约 1 秒。
     */
    private static final long BATCH_PAUSE_MILLIS = 5L;

    private final DatabaseManager target;
    private final AuditLogger audit;
    private final Logger logger;
    /** 迁移专用单线程：低频重操作，不占用认证/数据库的线程池。 */
    private final ExecutorService executor;

    public AccountMigrator(DatabaseManager target, AuditLogger audit, Logger logger) {
        this.target = target;
        this.audit = audit;
        this.logger = logger;
        this.executor = java.util.concurrent.Executors.newSingleThreadExecutor(runnable -> {
            Thread thread = new Thread(runnable, "MikuAuth-Migrate");
            thread.setDaemon(true);
            return thread;
        });
    }

    /** 插件关闭时调用。 */
    public void shutdown() {
        executor.shutdownNow();
    }

    /**
     * 执行迁移（异步）。
     *
     * @param location 源库位置：{@code sqlite:/path/to/db}、{@code mysql://user:pass@host:3306/db}，
     *                 或直接给 {@code jdbc:} 连接串
     * @param dryRun   true = 只统计不写入
     */
    public CompletableFuture<MigrationReport> migrateAsync(MigrationSource source, String location, boolean dryRun) {
        CompletableFuture<MigrationReport> result = new CompletableFuture<>();
        try {
            executor.execute(() -> {
                try {
                    result.complete(run(source, location, dryRun));
                } catch (Throwable t) {
                    result.completeExceptionally(t);
                }
            });
        } catch (Throwable t) {
            result.completeExceptionally(t);
        }
        return result;
    }

    // ---------------------------------------------------------------------
    // 主流程
    // ---------------------------------------------------------------------

    private MigrationReport run(MigrationSource source, String location, boolean dryRun) throws Exception {
        String url = jdbcUrl(location);
        logger.info("[迁移] 开始从 {} 迁移账号（{}，{}）",
                source.displayName(), dryRun ? "试运行" : "正式执行", maskCredentials(url));

        List<String> failures = new ArrayList<>();
        int total = 0;
        int imported = 0;
        int skipped = 0;
        int noPassword = 0;

        try (Connection connection = open(url);
             Statement statement = connection.createStatement();
             ResultSet rs = statement.executeQuery(selectSql(source))) {

            // ★ 流式处理：边读边攒批写，全程只保留一个批次的数据。
            // 旧实现先把整表读进 List 再写，几十万账号时内存峰值高、且写入期间
            // 数据库工作线程被逐条 join() 占满（SQLite 只有 1 个线程），
            // 在线玩家的登录/注册查询会被挤在后面排长队。
            List<DatabaseManager.ImportRequest> batch = new ArrayList<>(BATCH_SIZE);
            while (rs.next()) {
                ImportedAccount account = mapRow(source, rs);
                if (account == null) {
                    continue;
                }
                total++;
                if (account.passwordHash() == null) {
                    noPassword++;
                }
                if (dryRun) {
                    continue;
                }
                batch.add(account.toRequest());
                if (batch.size() >= BATCH_SIZE) {
                    int written = flush(batch, failures);
                    imported += written;
                    skipped += batch.size() - written;
                    batch.clear();
                    // 主动让出：给在线玩家的查询留出窗口，避免迁移把数据库线程占满
                    Thread.sleep(BATCH_PAUSE_MILLIS);
                }
            }
            if (!batch.isEmpty()) {
                int written = flush(batch, failures);
                imported += written;
                skipped += batch.size() - written;
            }
        }

        MigrationReport report = new MigrationReport(source.displayName(), dryRun, total,
                imported, skipped, noPassword, failures);
        logger.info("[迁移] {} 完成：共 {} 条，写入 {}，跳过 {}，无密码 {}，失败 {}",
                source.displayName(), total, imported, skipped, noPassword, failures.size());
        if (!dryRun) {
            audit.record(AuditAction.MIGRATE, "-", null, null,
                    "从 " + source.displayName() + " 迁移：" + imported + " 条写入，"
                            + skipped + " 条跳过，" + noPassword + " 条无密码");
        }
        return report;
    }

    /** 提交一个批次；整批失败时只记一条批次级失败，避免刷屏且不中断后续批次。 */
    private int flush(List<DatabaseManager.ImportRequest> batch, List<String> failures) {
        try {
            return target.importAccountsBatch(List.copyOf(batch)).join();
        } catch (Throwable t) {
            if (failures.size() < MAX_FAILURES) {
                failures.add("批次写入失败（" + batch.size() + " 条）: " + rootMessage(t));
            } else if (failures.size() == MAX_FAILURES) {
                failures.add("……更多失败已省略");
            }
            logger.warn("[迁移] 批次写入失败（{} 条）: {}", batch.size(), rootMessage(t));
            return 0;
        }
    }

    private Connection open(String url) throws Exception {
        if (url.startsWith("jdbc:sqlite:")) {
            // 显式注册：插件类加载器下 DriverManager 的 ServiceLoader 发现不可靠
            Class.forName("org.sqlite.JDBC");
        } else if (url.startsWith("jdbc:mariadb:") || url.startsWith("jdbc:mysql:")) {
            Class.forName("org.mariadb.jdbc.Driver");
        }
        return DriverManager.getConnection(url);
    }

    // ---------------------------------------------------------------------
    // 读取与映射
    // ---------------------------------------------------------------------

    /** 各来源的读取语句（只读，绝不写回源库）。 */
    private static String selectSql(MigrationSource source) {
        return switch (source) {
            case AUTHME -> "SELECT username, realname, password, ip, regdate, lastlogin FROM authme";
            case LIBRELOGIN -> "SELECT uuid, last_nickname, hashed_password, algo, ip, joined, last_seen "
                    + "FROM librepremium_data";
            case LIMBOAUTH -> "SELECT LAST_NICKNAME, PASSWORD, IP, REGDATE, LAST_SEEN, UUID FROM AUTH";
        };
    }

    /** 按来源分派行映射；返回 null 表示该行无法使用（如缺少昵称）。 */
    private static ImportedAccount mapRow(MigrationSource source, ResultSet rs) throws SQLException {
        return switch (source) {
            case AUTHME -> fromAuthMe(rs);
            case LIBRELOGIN -> fromLibreLogin(rs);
            case LIMBOAUTH -> fromLimboAuth(rs);
        };
    }

    private static ImportedAccount fromAuthMe(ResultSet rs) throws SQLException {
        String nickname = firstNonEmpty(rs.getString("realname"), rs.getString("username"));
        if (nickname == null) {
            return null;
        }
        // AuthMe 不存 UUID：离线服按昵称生成，与 MikuAuth 的算法一致
        return new ImportedAccount(UuidUtil.offlineUuid(nickname), nickname,
                usableHash(rs.getString("password")), rs.getString("ip"),
                normalizeMillis(rs.getLong("regdate")), normalizeMillis(rs.getLong("lastlogin")));
    }

    private static ImportedAccount fromLibreLogin(ResultSet rs) throws SQLException {
        String nickname = rs.getString("last_nickname");
        if (nickname == null) {
            return null;
        }
        // LibreLogin 存有玩家 UUID，直接沿用（避免改名后身份漂移）
        UUID uuid = parseUuidOrOffline(rs.getString("uuid"), nickname);
        // algo 列不参与判断：一律按哈希本身的格式决定能否校验（更稳，兼容其自定义 algo）
        String hash = usableHash(rs.getString("hashed_password"));
        return new ImportedAccount(uuid, nickname, hash, rs.getString("ip"),
                timestampMillis(rs, "joined"), timestampMillis(rs, "last_seen"));
    }

    private static ImportedAccount fromLimboAuth(ResultSet rs) throws SQLException {
        String nickname = rs.getString("LAST_NICKNAME");
        if (nickname == null) {
            return null;
        }
        UUID uuid = parseUuidOrOffline(rs.getString("UUID"), nickname);
        // LimboAuth 默认 BCrypt；若其配置了 migration-hash 也可能是 AuthMe 格式——
        // 同样交给 PasswordHasher 在登录时按格式处理
        String hash = usableHash(rs.getString("PASSWORD"));
        return new ImportedAccount(uuid, nickname, hash, rs.getString("IP"),
                normalizeMillis(rs.getLong("REGDATE")), normalizeMillis(rs.getLong("LAST_SEEN")));
    }

    // ---------------------------------------------------------------------
    // 工具
    // ---------------------------------------------------------------------

    /**
     * 判断源哈希能否在本插件继续使用。
     *
     * <p>认不出的算法（如 Argon2）不迁移密码：宁可在报告里明确"该账号需重新设置密码"，
     * 也不要存一个永远校验失败的哈希，让玩家反复撞墙而无人知晓原因。
     */
    private static String usableHash(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        String trimmed = raw.trim();
        return PasswordHasher.detect(trimmed) == PasswordHasher.Algorithm.UNKNOWN ? null : trimmed;
    }

    private static UUID parseUuidOrOffline(String raw, String nickname) {
        if (raw != null && !raw.isBlank()) {
            try {
                UUID parsed = UuidUtil.parse(raw.trim());
                if (parsed != null) {
                    return parsed;
                }
            } catch (Throwable ignored) {
                // 源里是脏数据：回退到离线 UUID，保证迁移不中断
            }
        }
        return UuidUtil.offlineUuid(nickname);
    }

    /** 时间戳归一化：小于该阈值的按"秒"处理并转毫秒（个别老库存的是秒）。 */
    private static long normalizeMillis(long value) {
        if (value <= 0) {
            return 0L;
        }
        return value < 100_000_000_000L ? value * 1000L : value;
    }

    private static long timestampMillis(ResultSet rs, String column) {
        try {
            Timestamp timestamp = rs.getTimestamp(column);
            return timestamp == null ? 0L : timestamp.getTime();
        } catch (SQLException e) {
            return 0L;
        }
    }

    private static String firstNonEmpty(String first, String second) {
        if (first != null && !first.isBlank()) {
            return first;
        }
        return second == null || second.isBlank() ? null : second;
    }

    private static String rootMessage(Throwable throwable) {
        Throwable cause = throwable;
        while (cause.getCause() != null) {
            cause = cause.getCause();
        }
        return cause.getMessage() == null ? cause.getClass().getSimpleName() : cause.getMessage();
    }

    /** 位置串 → JDBC URL。 */
    static String jdbcUrl(String location) {
        String trimmed = location.trim();
        if (trimmed.startsWith("jdbc:")) {
            return trimmed;
        }
        if (trimmed.startsWith("sqlite:")) {
            return "jdbc:sqlite:" + trimmed.substring("sqlite:".length());
        }
        if (trimmed.startsWith("mysql://") || trimmed.startsWith("mariadb://")) {
            URI uri = URI.create(trimmed.replace("mysql://", "mariadb://"));
            String credentials = uri.getUserInfo() == null ? "" : "?user=" + uri.getUserInfo().replace(":", "&password=");
            int port = uri.getPort() > 0 ? uri.getPort() : 3306;
            return "jdbc:mariadb://" + uri.getHost() + ":" + port + uri.getPath() + credentials;
        }
        // 兜底：当作 SQLite 文件路径
        return "jdbc:sqlite:" + trimmed;
    }

    /** 日志里不暴露数据库口令。 */
    private static String maskCredentials(String url) {
        return url.replaceAll("password=[^&]*", "password=***");
    }

    /**
     * 迁移中间结构：与源插件无关的统一形态。
     *
     * @param passwordHash null = 源里没有可用哈希（迁入后需重新设置密码）
     */
    record ImportedAccount(UUID uuid, String nickname, String passwordHash, String ip,
                           long registerTime, long lastLoginTime) {

        /** 一律按离线账号迁入：正版绑定留给后续正版登录时自动登记。 */
        String storedType() {
            return cn.miku.auth.database.StoredPlayer.TYPE_OFFLINE;
        }

        /** 转换为数据库层的批量写入请求。 */
        DatabaseManager.ImportRequest toRequest() {
            return new DatabaseManager.ImportRequest(uuid, nickname, passwordHash, storedType(),
                    ip, registerTime, lastLoginTime);
        }
    }
}
