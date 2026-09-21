package cn.miku.auth.premium;

import java.util.Locale;
import java.util.UUID;

/**
 * 单个正版查询源：请求一个 API 并解析结果。
 * 无状态，可在任意线程并发调用。
 *
 * <p>非 final：测试可继承并覆写 {@link #resolve(String)} 以注入确定性的结果。
 */
class PremiumResolver {

    private final ResolverConfig config;
    private final int timeoutMillis;

    PremiumResolver(ResolverConfig config, int timeoutMillis) {
        this.config = config;
        this.timeoutMillis = timeoutMillis;
    }

    String id() {
        return config.id();
    }

    /**
     * 执行一次查询。任何失败都以 UNKNOWN 收尾，绝不抛出异常。
     */
    PremiumResolution resolve(String username) {
        try {
            HttpJsonClient.HttpJsonResponse response = HttpJsonClient.get(config.endpoint(), username, timeoutMillis);
            int status = response.statusCode();

            // 明确“无此正版账号” → 离线
            if (config.isNotFound(status)) {
                return PremiumResolution.offline(config.id(), "http " + status);
            }
            // 200 → 解析 UUID 与规范昵称
            if (status == 200) {
                return parseBody(response.body(), username);
            }
            // 其余状态码 → 无法判定
            return PremiumResolution.unknown(config.id(), "http " + status);
        } catch (Exception e) {
            return PremiumResolution.unknown(config.id(), e.getClass().getSimpleName());
        }
    }

    private PremiumResolution parseBody(String body, String username) {
        String uuidRaw = HttpJsonClient.extractStringField(body, config.uuidField());
        String nameRaw = HttpJsonClient.extractStringField(body, config.nameField());
        if (uuidRaw == null || nameRaw == null) {
            return PremiumResolution.unknown(config.id(), "响应缺少字段");
        }

        UUID uuid = parseUuid(uuidRaw);
        if (uuid == null || (uuid.getMostSignificantBits() == 0L && uuid.getLeastSignificantBits() == 0L)) {
            return PremiumResolution.unknown(config.id(), "UUID 解析失败");
        }
        // 规范昵称与请求昵称大小写不敏感地一致才可信（防止镜像站返回错误档案）
        if (!nameRaw.equalsIgnoreCase(username)) {
            return PremiumResolution.offline(config.id(), "昵称不匹配");
        }
        return PremiumResolution.premium(uuid, nameRaw, config.id());
    }

    /** Mojang 返回无连字符的 32 位原始 UUID；镜像源返回标准格式。 */
    private UUID parseUuid(String raw) {
        try {
            if (config.usesRawUuid() && raw.length() == 32 && raw.indexOf('-') < 0) {
                String dashed = raw.substring(0, 8) + "-" + raw.substring(8, 12) + "-"
                        + raw.substring(12, 16) + "-" + raw.substring(16, 20) + "-" + raw.substring(20);
                return UUID.fromString(dashed);
            }
            return UUID.fromString(raw);
        } catch (IllegalArgumentException | StringIndexOutOfBoundsException e) {
            return null;
        }
    }

    /** 昵称格式校验（Minecraft 规则：3-16 位字母数字下划线）。 */
    static boolean isValidUsername(String username) {
        if (username == null || username.length() < 3 || username.length() > 16) {
            return false;
        }
        for (int i = 0; i < username.length(); i++) {
            char c = username.charAt(i);
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_')) {
                return false;
            }
        }
        return true;
    }

    /** 归一化缓存键。 */
    static String cacheKey(String username) {
        return username.toLowerCase(Locale.ROOT);
    }
}
