package cn.miku.auth.premium;

import java.net.HttpURLConnection;

/**
 * 正版查询源配置（数据驱动，避免为每个 API 写重复代码）。
 *
 * <p>代码来源于 VeloAuth（已获授权使用）并保持一致的端点定义：
 * <ul>
 *   <li><b>Mojang</b>：官方 API，<b>权威源</b>。昵称不存在时返回 204 或 404（官方行为不固定，两者都接受）；
 *       UUID 为无连字符的 32 位原始格式，字段名为 {@code id} / {@code name}；</li>
 *   <li><b>Ashcon</b>：镜像 API，404 = 不存在，标准 UUID 格式，字段 {@code uuid} / {@code username}；
 *       数据来自缓存，存在滞后，<b>非权威</b>；</li>
 *   <li><b>WPME</b>：镜像 API，404 = 不存在，标准 UUID 格式，字段 {@code uuid} / {@code username}，
 *       <b>非权威</b>。</li>
 * </ul>
 */
public enum ResolverConfig {

    MOJANG(
            "mojang",
            "https://api.mojang.com/users/profiles/minecraft/",
            -1,          // 哨兵值：同时接受 204 与 404 视为“不存在”
            "id",
            "name",
            true,
            true),
    ASHCON(
            "ashcon",
            "https://api.ashcon.app/mojang/v2/user/",
            HttpURLConnection.HTTP_NOT_FOUND,
            "uuid",
            "username",
            false,
            false),
    WPME(
            "wpme",
            "https://api-mc.wpme.pl/v2/user/",
            HttpURLConnection.HTTP_NOT_FOUND,
            "uuid",
            "username",
            false,
            false);

    private final String id;
    private final String endpoint;
    private final int notFoundCode;
    private final String uuidField;
    private final String nameField;
    private final boolean rawUuidFormat;
    /** 是否为权威源：只有权威源的结论才允许驱动破坏性动作（清理记录）与负缓存。 */
    private final boolean authoritative;

    ResolverConfig(String id, String endpoint, int notFoundCode,
                   String uuidField, String nameField, boolean rawUuidFormat, boolean authoritative) {
        this.id = id;
        this.endpoint = endpoint;
        this.notFoundCode = notFoundCode;
        this.uuidField = uuidField;
        this.nameField = nameField;
        this.rawUuidFormat = rawUuidFormat;
        this.authoritative = authoritative;
    }

    /** 是否权威源（Mojang 官方 API）。 */
    public boolean authoritative() {
        return authoritative;
    }

    public String id() {
        return id;
    }

    public String endpoint() {
        return endpoint;
    }

    /** 判断 HTTP 状态码是否表示“该昵称无正版账号”。 */
    public boolean isNotFound(int statusCode) {
        if (notFoundCode == -1) {
            return statusCode == HttpURLConnection.HTTP_NO_CONTENT
                    || statusCode == HttpURLConnection.HTTP_NOT_FOUND;
        }
        return statusCode == notFoundCode;
    }

    public String uuidField() {
        return uuidField;
    }

    public String nameField() {
        return nameField;
    }

    public boolean usesRawUuid() {
        return rawUuidFormat;
    }
}
