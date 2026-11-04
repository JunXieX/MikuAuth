package cn.miku.auth.paper;

import org.bukkit.configuration.file.FileConfiguration;

/**
 * config.yml 的类型化读取。
 *
 * <p>所有数值都做区间钳制：这些值直接决定密码策略与超时行为，配错时宁可静默压回安全区间，
 * 也不能让"最小长度 0"或"超时 0 秒"这类值生效。
 */
public final class PaperConfig {

    private final MikuAuthPlugin plugin;

    PaperConfig(MikuAuthPlugin plugin) {
        this.plugin = plugin;
    }

    private FileConfiguration raw() {
        return plugin.getConfig();
    }

    private int clamped(String path, int def, int min, int max) {
        int value = raw().getInt(path, def);
        int result = Math.max(min, Math.min(max, value));
        if (result != value) {
            plugin.getLogger().warning("[配置] " + path + " = " + value + " 超出允许范围 [" + min + ", " + max
                    + "]，已按 " + result + " 使用");
        }
        return result;
    }

    public int minPasswordLength() {
        return clamped("registration.min-password-length", 4, 1, 64);
    }

    /** 上限不低于下限：否则没有任何密码能通过校验，而提示只会说"长度不符"。 */
    public int maxPasswordLength() {
        return Math.max(clamped("registration.max-password-length", 32, 1, 128), minPasswordLength());
    }

    public int maxAccountsPerIp() {
        return Math.max(0, raw().getInt("registration.max-accounts-per-ip", 5));
    }

    public int maxTries() {
        return clamped("login.max-tries", 5, 1, 100);
    }

    public int timeoutSeconds() {
        return clamped("login.timeout-seconds", 60, 5, 600);
    }

    public int bcryptCost() {
        return clamped("login.bcrypt-cost", 10, 8, 16);
    }

    public int securityMaxFailures() {
        return Math.max(0, raw().getInt("security.max-failures", 5));
    }

    public int securityWindowMinutes() {
        return clamped("security.failure-window-minutes", 15, 1, 1440);
    }

    public int securityLockoutMinutes() {
        return clamped("security.lockout-minutes", 5, 1, 1440);
    }

    public boolean allowCloseWithEscape() {
        return raw().getBoolean("dialog.allow-close-with-escape", false);
    }

    public boolean auditEnabled() {
        return raw().getBoolean("audit.enabled", true);
    }

    public int auditRetainDays() {
        return clamped("audit.retain-days", 30, 0, 3650);
    }

    public String databaseType() {
        return raw().getString("database.type", "sqlite").trim().toLowerCase(java.util.Locale.ROOT);
    }

    public String databaseFile() {
        return raw().getString("database.file", "auth.db");
    }

    public String mariaDbHost() {
        return raw().getString("database.mariadb.host", "127.0.0.1");
    }

    public int mariaDbPort() {
        return clamped("database.mariadb.port", raw().getInt("database.mariadb.port", 3306), 1, 65535);
    }

    public String mariaDbDatabase() {
        return raw().getString("database.mariadb.database", "mikuauth");
    }

    public String mariaDbUsername() {
        return raw().getString("database.mariadb.username", "mikuauth");
    }

    public String mariaDbPassword() {
        return raw().getString("database.mariadb.password", "");
    }
}
