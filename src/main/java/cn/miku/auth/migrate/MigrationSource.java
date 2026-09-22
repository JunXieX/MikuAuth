package cn.miku.auth.migrate;

/**
 * 支持的账号来源。
 *
 * <p>表结构与密码格式均已对照各自官方实现确认（见 {@link AccountMigrator} 的映射代码）：
 * <ul>
 *   <li><b>AuthMe</b>（AuthMeReloaded，最流行的离线认证插件）：
 *       表 {@code authme}，密码可为 {@code $SHA$salt$hash}、{@code $SHA512$salt$hash}、
 *       BCrypt 或早期版本的 MD5；</li>
 *   <li><b>LibreLogin</b>：表 {@code librepremium_data}，
 *       列 {@code hashed_password / salt / algo}，默认 BCrypt；</li>
 *   <li><b>LimboAuth</b>：表 {@code AUTH}，
 *       列 {@code LAST_NICKNAME / PASSWORD / UUID / ...}，默认 BCrypt。</li>
 * </ul>
 */
public enum MigrationSource {

    AUTHME("AuthMe"),
    LIBRELOGIN("LibreLogin"),
    LIMBOAUTH("LimboAuth");

    private final String displayName;

    MigrationSource(String displayName) {
        this.displayName = displayName;
    }

    public String displayName() {
        return displayName;
    }

    /** 解析用户输入（大小写不敏感，接受常见别名）。 */
    public static MigrationSource parse(String raw) {
        if (raw == null) {
            return null;
        }
        String key = raw.trim().toLowerCase(java.util.Locale.ROOT);
        return switch (key) {
            case "authme", "authmereloaded", "am" -> AUTHME;
            case "librelogin", "libre", "ll" -> LIBRELOGIN;
            case "limboauth", "limbo", "la" -> LIMBOAUTH;
            default -> null;
        };
    }

    /** 命令用法提示。 */
    public static String usage() {
        return "authme | librelogin | limboauth";
    }
}
