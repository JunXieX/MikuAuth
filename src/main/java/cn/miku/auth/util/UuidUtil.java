package cn.miku.auth.util;

import com.velocitypowered.api.util.UuidUtils;

import java.util.UUID;

/**
 * 账号 UUID 工具：账号身份键的统一生成与解析。
 *
 * <p><b>为什么身份键是 UUID 而不是昵称</b>：
 * <ul>
 *   <li><b>正版账号 = Mojang UUID</b>：玩家在 Mojang 改名后 UUID 不变，
 *       账号数据自动跟随，旧昵称随之释放 —— 这是"防止死昵称"的基础；</li>
 *   <li><b>离线账号 = 离线 UUID</b>（由昵称推导）：离线模式下"账号即昵称"，
 *       这是唯一可行的身份，改名等于换号。</li>
 * </ul>
 *
 * <p>离线 UUID 直接委托 Velocity 的 {@link UuidUtils#generateOfflinePlayerUuid(String)}，
 * <b>不自己实现 MD5</b>：算法必须与代理分配给玩家的 UUID 完全一致，
 * 否则同一个离线玩家会被算成两个身份，账号数据无法命中。
 */
public final class UuidUtil {

    private UuidUtil() {
    }

    /** 由昵称推导离线 UUID（与代理分配的一致）。 */
    public static UUID offlineUuid(String username) {
        return UuidUtils.generateOfflinePlayerUuid(username);
    }

    /**
     * 解析存储的 UUID 字符串；null/空/非法一律返回 null。
     *
     * <p><b>不接受"宽松写法"</b>：JDK 的 {@code UUID.fromString} 是宽松实现，
     * {@code "1-2-3-4-5"} 也会返回一个合法但错误的 UUID。这里解析后回比一次规范形式，
     * 只有「标准 36 位带连字符」或「Mojang 的 32 位十六进制」才认，其余返回 null ——
     * 迁移外部旧库时，畸形值必须被当成"无效"而不是静默变成一个错误身份键。
     */
    public static UUID parse(String text) {
        if (text == null || text.isBlank()) {
            return null;
        }
        String trimmed = text.trim();
        if (trimmed.length() == 32 && trimmed.indexOf('-') < 0 && isHex(trimmed)) {
            // Mojang 原始格式：补上连字符
            String dashed = trimmed.substring(0, 8) + "-" + trimmed.substring(8, 12) + "-"
                    + trimmed.substring(12, 16) + "-" + trimmed.substring(16, 20) + "-"
                    + trimmed.substring(20);
            return parseCanonical(dashed);
        }
        return parseCanonical(trimmed);
    }

    private static UUID parseCanonical(String text) {
        try {
            UUID parsed = UUID.fromString(text);
            return parsed.toString().equalsIgnoreCase(text) ? parsed : null;
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static boolean isHex(String text) {
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            boolean hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            if (!hex) {
                return false;
            }
        }
        return true;
    }

    /** 统一的存储格式：小写带连字符（{@link UUID#toString()} 即此格式）。 */
    public static String format(UUID uuid) {
        return uuid == null ? null : uuid.toString();
    }
}
