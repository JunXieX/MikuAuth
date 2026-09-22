package cn.miku.auth.config;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import org.slf4j.Logger;

/**
 * config.yml 配置读取（带内置默认值回退）。
 *
 * <p>回退机制：用户配置文件缺键时自动使用插件内置默认值，
 * 因此插件升级新增配置项后无需重写用户文件（保留用户注释与排版）。
 * 用户文件不存在时直接复制内置默认文件（含完整中文注释）。
 *
 * <p>查找与缓存细节见 {@link YamlStore}。
 */
public final class MikuConfig {

    /** 内置默认配置资源路径。 */
    private static final String DEFAULT_RESOURCE = "/config.yml";

    private final YamlStore store = new YamlStore();

    /** 命令别名缓存：命令拦截是热路径，且别名只在 reload 时变化。 */
    private volatile List<String> loginAliases = List.of("l", "log");
    private volatile List<String> registerAliases = List.of("reg");
    private volatile List<String> changePasswordAliases = List.of("cp", "changepw");

    /** 运行时 IP 限号覆盖（/mikuauth limit 设置），null 表示未覆盖。 */
    private volatile Integer maxAccountsPerIpOverride;

    /**
     * 加载配置。
     *
     * @param dataDirectory 插件数据目录
     * @param logger        日志（用于提示缺失的顶层配置段）
     */
    public void load(Path dataDirectory, Logger logger) throws IOException {
        store.load(dataDirectory.resolve("config.yml"), DEFAULT_RESOURCE, logger);

        if (logger != null) {
            for (String key : store.defaultTopLevelKeys()) {
                if (!store.userTopLevelKeys().contains(key)) {
                    logger.warn("[MikuAuth] 配置缺少顶层段落 '{}'，已使用内置默认值。", key);
                }
            }
            validateAndWarn(logger);
        }
        // 别名在加载后解析一次并缓存（命令注册与命令拦截共用，必须保持一致）
        this.loginAliases = getStringList("commands.login-aliases", List.of("l", "log"));
        this.registerAliases = getStringList("commands.register-aliases", List.of("reg"));
        this.changePasswordAliases = getStringList("commands.changepassword-aliases", List.of("cp", "changepw"));
    }

    // ---------------------------------------------------------------------
    // 服务器与调度
    // ---------------------------------------------------------------------

    /** 认证服务器名（玩家必须先在此服完成登录/注册）。 */
    public String authServer() {
        return getString("server.auth-server", "auth");
    }

    /** 认证完成后送回的服务器；留空表示使用 velocity.toml 的 try 列表第一个。 */
    public String fallbackServer() {
        return getString("server.fallback-server", "");
    }

    // ---------------------------------------------------------------------
    // 正版（Java 版）验证
    // ---------------------------------------------------------------------

    public boolean premiumEnabled() {
        return getBoolean("premium.enabled", true);
    }

    public boolean premiumMojangEnabled() {
        return getBoolean("premium.mojang", true);
    }

    public boolean premiumAshconEnabled() {
        return getBoolean("premium.ashcon", true);
    }

    public boolean premiumWpmeEnabled() {
        return getBoolean("premium.wpme", true);
    }

    /** 上游 API 请求超时（毫秒）。 */
    public int premiumTimeoutMillis() {
        return clamp(getInt("premium.timeout-millis", 5000), 300, 30000);
    }

    /** 正版命中结果缓存时长（分钟），0 = 不缓存。 */
    public int premiumHitTtlMinutes() {
        return Math.max(0, getInt("premium.hit-ttl-minutes", 60));
    }

    /** 离线（未命中）结果缓存时长（分钟），0 = 不缓存。 */
    public int premiumMissTtlMinutes() {
        return Math.max(0, getInt("premium.miss-ttl-minutes", 10));
    }

    /**
     * 正版玩家改名后是否自动迁移账号数据并释放旧昵称（默认开启）。
     *
     * <p>关闭后：改名会在新昵称下重新登记一条记录，旧昵称的记录留在库里，
     * 那个昵称会一直不可用（"死昵称"），只能由管理员手工处理。
     */
    public boolean autoMigrateRenamed() {
        return getBoolean("premium.auto-migrate-renamed", true);
    }

    /** 三个验证源全部失败时，是否拒绝未注册玩家进入（防止正版昵称被抢注）。 */
    public boolean premiumFailClosed() {
        return getBoolean("premium.fail-closed", true);
    }

    // ---------------------------------------------------------------------
    // 基岩版（Floodgate）
    // ---------------------------------------------------------------------

    public boolean bedrockAutoLogin() {
        return getBoolean("bedrock.auto-login", true);
    }

    /** Floodgate 用户名前缀兜底值（实际前缀以 Floodgate API 为准）。 */
    public String bedrockPrefix() {
        return getString("bedrock.username-prefix", ".");
    }

    // ---------------------------------------------------------------------
    // 会话（同 IP 免密）
    //
    // 这是离线账号唯一的免密途径：登录后一段时间内从同一 IP 再次进入免密。
    // 注意：曾尝试用原版 Cookie 实现"记住设备"，但原版客户端的 Cookie 只在内存中、
    //       断开连接即丢失（仅在一次连接及其 transfer 转移内有效），无法跨会话使用。
    // ---------------------------------------------------------------------

    /** 会话免密总开关。 */
    public boolean sessionEnabled() {
        return getBoolean("session.enabled", true);
    }

    /** 登录后会话时长（分钟），期间同 IP 再次进入免密。 */
    public int sessionDurationMinutes() {
        return clamp(getInt("session.duration-minutes", 60), 1, 10080);
    }

    /**
     * 免密进入时是否续期会话（滑动窗口）。
     *
     * <p>true：有效期内从同一 IP 进入即顺延一个完整时长（活跃玩家无需反复输密码）；
     * false：会话从上次密码登录起硬性到期。
     */
    public boolean sessionRenewOnLogin() {
        return getBoolean("session.renew-on-session-login", true);
    }

    // ---------------------------------------------------------------------
    // 审计日志
    // ---------------------------------------------------------------------

    /** 是否记录登录审计日志。 */
    public boolean auditEnabled() {
        return getBoolean("audit.enabled", true);
    }

    /** 审计日志保留天数；0 = 永久保留。 */
    public int auditRetainDays() {
        return clamp(getInt("audit.retain-days", 30), 0, 3650);
    }

    /** 单次查询返回的最大条数（/mikuauth audit）。 */
    public int auditQueryLimit() {
        return clamp(getInt("audit.query-limit", 20), 1, 200);
    }

    /**
     * 昵称冲突记录文件名（相对数据目录）。
     *
     * <p>记录"同名连接已在线、本次连接被顶下线"（重复登录冲突）的事件，
     * 单独落盘便于管理员事后核对。
     *
     * <p>注意：玩家使用「已属于正版账号的昵称」但以离线客户端连接时，失败发生在加密握手阶段，
     * 该阶段 Velocity 不产生任何事件，因此这类失败不会出现在本文件中
     * （详见 {@code AuthManager#logJoinFailure}）。
     *
     * @return 空字符串表示关闭该记录
     */
    public String premiumConflictLogFile() {
        return getString("audit.premium-conflict-file", "premium-conflicts.log");
    }

    /**
     * 后端拒绝进入记录文件名（相对数据目录）。
     *
     * <p>记录"玩家已通过认证、但被目标服（或其上的插件，如验证网关/白名单）直接踢回"的事件，
     * 内容为目标服给出的原因（同一条原因也会转发到玩家聊天栏）。
     *
     * <p>不含原因的连接故障（目标服离线等）不会写入本文件——它们由转服调度自动重试。
     *
     * @return 空字符串表示关闭该记录
     */
    public String backendKickLogFile() {
        return getString("audit.backend-kick-file", "backend-kicks.log");
    }

    // ---------------------------------------------------------------------
    // 账号迁移
    // ---------------------------------------------------------------------

    /**
     * 迁移位置白名单（逗号分隔的前缀）。
     *
     * <p>迁移的"位置"参数会让服务器以本机身份去连接目标库（可读本机 SQLite 文件、
     * 也可向任意主机发起 MySQL 连接）。若填了白名单，则只允许前缀匹配的位置，
     * 从而把这一能力限制在预期的数据源上。
     *
     * @return 空字符串 = 不限制（默认，便于迁移时直接可用）
     */
    public String migrateAllowedPrefixes() {
        return getString("migrate.allowed-prefixes", "");
    }

    // ---------------------------------------------------------------------
    // 注册
    // ---------------------------------------------------------------------

    /** 密码最小长度。 */
    public int minPasswordLength() {
        return clamp(getInt("registration.min-password-length", 6), 1, 64);
    }

    /** 密码最大长度。 */
    public int maxPasswordLength() {
        return clamp(getInt("registration.max-password-length", 32), 1, 128);
    }

    /** 每 IP 可注册的账号上限；0 = 不限制。运行时可用 /mikuauth limit 临时覆盖。 */
    public int maxAccountsPerIp() {
        Integer override = maxAccountsPerIpOverride;
        return override != null ? override : Math.max(0, getInt("registration.max-accounts-per-ip", 3));
    }

    /** 运行时覆盖 IP 限号（不写入配置文件，重启后失效）。 */
    public void setMaxAccountsPerIpOverride(int value) {
        this.maxAccountsPerIpOverride = Math.max(0, value);
    }

    // ---------------------------------------------------------------------
    // 登录
    // ---------------------------------------------------------------------

    /** 单次连接内的密码最大尝试次数，超过踢出；0 = 不限。 */
    public int maxLoginTries() {
        return Math.max(0, getInt("login.max-tries", 5));
    }

    /** 认证超时（秒），超时踢出；0 = 不超时。 */
    public int authTimeoutSeconds() {
        return Math.max(0, getInt("login.timeout-seconds", 60));
    }

    /** BCrypt 成本因子。 */
    public int bcryptCost() {
        return clamp(getInt("login.bcrypt-cost", 10), 4, 31);
    }

    // ---------------------------------------------------------------------
    // Dialog 对话框
    // ---------------------------------------------------------------------

    /** 延迟多久再弹对话框（毫秒）：避开子服 Join Game 包竞争。 */
    public int dialogShowDelayMillis() {
        return clamp(getInt("dialog.show-delay-millis", 700), 0, 10000);
    }

    // ---------------------------------------------------------------------
    // 显示
    // ---------------------------------------------------------------------

    public boolean titleEnabled() {
        return getBoolean("display.title", true);
    }

    public boolean bossBarEnabled() {
        return getBoolean("display.bossbar", true);
    }

    public String bossBarColor() {
        return getString("display.bossbar-color", "YELLOW");
    }

    public String bossBarOverlay() {
        return getString("display.bossbar-overlay", "PROGRESS");
    }

    // ---------------------------------------------------------------------
    // 数据库
    // ---------------------------------------------------------------------

    /** 数据库后端类型：sqlite（默认）/ mariadb。 */
    public String databaseType() {
        return getString("database.type", "sqlite").trim().toLowerCase(Locale.ROOT);
    }

    /** SQLite 数据库文件名（存放在插件数据目录下）。 */
    public String databaseFile() {
        return getString("database.file", "database.db");
    }

    public String mariaDbHost() {
        return getString("database.mariadb.host", "127.0.0.1");
    }

    public int mariaDbPort() {
        return clamp(getInt("database.mariadb.port", 3306), 1, 65535);
    }

    public String mariaDbDatabase() {
        return getString("database.mariadb.database", "mikuauth");
    }

    public String mariaDbUsername() {
        return getString("database.mariadb.username", "mikuauth");
    }

    public String mariaDbPassword() {
        return getString("database.mariadb.password", "");
    }

    /** 连接池大小：同时决定数据库操作的并发线程数。 */
    public int mariaDbPoolSize() {
        return clamp(getInt("database.mariadb.pool-size", 6), 2, 32);
    }

    /** 获取连接的超时（毫秒）。 */
    public int mariaDbConnectionTimeoutMillis() {
        return clamp(getInt("database.mariadb.connection-timeout-millis", 5000), 500, 60000);
    }

    /** TLS 模式：disable / trust / verify-ca / verify-full（默认 disable，内网直连）。 */
    public String mariaDbSslMode() {
        String mode = getString("database.mariadb.ssl-mode", "disable").trim().toLowerCase(Locale.ROOT);
        return switch (mode) {
            case "trust", "verify-ca", "verify-full" -> mode;
            default -> "disable";
        };
    }

    /**
     * 校验"取值带枚举语义"的配置项，非法值一律告警。
     *
     * <p>这些项在取值时是<b>静默回退默认值</b>的（例如 {@code ssl-mode} 拼错即回退 disable）。
     * 静默本身无害，但服主不知道"自己写错了、实际跑的是默认值"——而 ssl-mode 回退成
     * disable 意味着跨公网明文连接，属于和安全有关的静默降级。
     */
    private void validateAndWarn(Logger logger) {
        String sslMode = getString("database.mariadb.ssl-mode", "disable").trim().toLowerCase(Locale.ROOT);
        if (!Set.of("disable", "trust", "verify-ca", "verify-full").contains(sslMode)) {
            logger.warn("[配置] database.mariadb.ssl-mode '{}' 不是合法值，已按 disable 处理"
                    + "（可选：disable / trust / verify-ca / verify-full）", sslMode);
        }
        warnIfUnknownEnum(logger, "display.bossbar-color", bossBarColor(),
                Set.of("pink", "blue", "red", "green", "yellow", "purple", "white"));
        warnIfUnknownEnum(logger, "display.bossbar-overlay", bossBarOverlay(),
                Set.of("progress", "notched_6", "notched_10", "notched_12", "notched_20"));
    }

    /** 取值不在允许集合内时告警（解析侧仍按默认值继续）。 */
    private static void warnIfUnknownEnum(Logger logger, String path, String value, Set<String> allowed) {
        if (logger != null && value != null && !allowed.contains(value.trim().toLowerCase(Locale.ROOT))) {
            logger.warn("[配置] {} '{}' 不是合法值，已使用默认值（可选：{}）",
                    path, value, String.join(" / ", allowed));
        }
    }

    // ---------------------------------------------------------------------
    // 安全风控（跨会话失败计数与临时封禁）
    // ---------------------------------------------------------------------

    /** 触发临时封禁的连续失败次数；0 = 关闭该保护。 */
    public int securityMaxFailures() {
        return Math.max(0, getInt("security.max-failures", 5));
    }

    /** 失败计数窗口（分钟）：窗口内未再失败则计数清零。 */
    public int securityFailureWindowMinutes() {
        return clamp(getInt("security.failure-window-minutes", 15), 1, 1440);
    }

    /** 触发后的封禁时长（分钟）。 */
    public int securityLockoutMinutes() {
        return clamp(getInt("security.lockout-minutes", 5), 1, 1440);
    }

    // ---------------------------------------------------------------------
    // 命令别名
    // ---------------------------------------------------------------------

    public List<String> loginAliases() {
        return loginAliases;
    }

    public List<String> registerAliases() {
        return registerAliases;
    }

    public List<String> changePasswordAliases() {
        return changePasswordAliases;
    }

    // ---------------------------------------------------------------------
    // 底层取值
    // ---------------------------------------------------------------------

    private String getString(String path, String def) {
        Object value = store.lookup(path);
        return value != null ? String.valueOf(value) : def;
    }

    private int getInt(String path, int def) {
        Object value = store.lookup(path);
        if (value instanceof Number number) {
            return number.intValue();
        }
        if (value instanceof String text) {
            try {
                return Integer.parseInt(text.trim());
            } catch (NumberFormatException ignored) {
                // 配置写错时退回默认值
            }
        }
        return def;
    }

    private boolean getBoolean(String path, boolean def) {
        Object value = store.lookup(path);
        if (value instanceof Boolean bool) {
            return bool;
        }
        if (value instanceof String text) {
            return Boolean.parseBoolean(text.trim());
        }
        return def;
    }

    private List<String> getStringList(String path, List<String> def) {
        Object value = store.lookup(path);
        if (value instanceof List<?> list) {
            return List.copyOf(list.stream().map(String::valueOf).toList());
        }
        return def;
    }

    private static int clamp(int value, int min, int max) {
        return Math.max(min, Math.min(max, value));
    }

    /** 归一化昵称（统一小写比较）。 */
    public static String normalize(String nickname) {
        return nickname.toLowerCase(Locale.ROOT);
    }
}
