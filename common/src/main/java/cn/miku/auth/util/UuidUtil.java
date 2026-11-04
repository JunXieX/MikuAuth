package cn.miku.auth.util;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
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
 * <p><b>离线 UUID 自己算，不委托平台</b>：算法就是 Java 的 {@code UUID.nameUUIDFromBytes}
 * （MD5 + 版本 3 + IETF 变体），输入固定为 {@code "OfflinePlayer:" + 昵称}。
 * 代理端与纸端都必须与各自服务端分配给玩家的 UUID 完全一致，否则同一个离线玩家会被算成
 * 两个身份、账号数据永远命中不到。两端各调各自平台的工具方法虽然结果相同，但公共层无法
 * 同时依赖两个平台，因此这里实现唯一一份。
 */
public final class UuidUtil {

    private UuidUtil() {
    }

    /** 由昵称推导离线 UUID（与代理/服务端分配的一致）。 */
    public static UUID offlineUuid(String username) {
        if (username == null || username.isEmpty()) {
            throw new IllegalArgumentException("昵称不能为空");
        }
        return UUID.nameUUIDFromBytes(("OfflinePlayer:" + username).getBytes(StandardCharsets.UTF_8));
    }

    /** 规范化为带连字符的 36 位字符串（写库统一口径）；null 返回 null。 */
    public static String format(UUID uuid) {
        return uuid == null ? null : uuid.toString();
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
        if (text == null) {
            return null;
        }
        String trimmed = text.trim();
        if (trimmed.isEmpty()) {
            return null;
        }
        try {
            UUID parsed;
            if (trimmed.length() == 32) {
                // Mojang 的紧凑写法：补回连字符再交给 JDK
                parsed = UUID.fromString(trimmed.substring(0, 8) + "-" + trimmed.substring(8, 12) + "-"
                        + trimmed.substring(12, 16) + "-" + trimmed.substring(16, 20) + "-" + trimmed.substring(20));
            } else if (trimmed.length() == 36) {
                parsed = UUID.fromString(trimmed);
            } else {
                return null;
            }
            // 回比规范形式：排除 "1-2-3-4-5" 这类被 JDK 宽松解析出来的结果
            return parsed.toString().equalsIgnoreCase(trimmed) ? parsed : null;
        } catch (IllegalArgumentException invalid) {
            return null;
        }
    }

    /** 常量时间比较两个 UUID（迁移/查重时避免时序差异）。 */
    public static boolean sameUuid(UUID a, UUID b) {
        return MessageDigest.isEqual(
                uuidBytes(a), uuidBytes(b));
    }

    private static byte[] uuidBytes(UUID uuid) {
        if (uuid == null) {
            return new byte[16];
        }
        return new byte[]{
                (byte) (uuid.getMostSignificantBits() >> 56), (byte) (uuid.getMostSignificantBits() >> 48),
                (byte) (uuid.getMostSignificantBits() >> 40), (byte) (uuid.getMostSignificantBits() >> 32),
                (byte) (uuid.getMostSignificantBits() >> 24), (byte) (uuid.getMostSignificantBits() >> 16),
                (byte) (uuid.getMostSignificantBits() >> 8), (byte) uuid.getMostSignificantBits(),
                (byte) (uuid.getLeastSignificantBits() >> 56), (byte) (uuid.getLeastSignificantBits() >> 48),
                (byte) (uuid.getLeastSignificantBits() >> 40), (byte) (uuid.getLeastSignificantBits() >> 32),
                (byte) (uuid.getLeastSignificantBits() >> 24), (byte) (uuid.getLeastSignificantBits() >> 16),
                (byte) (uuid.getLeastSignificantBits() >> 8), (byte) uuid.getLeastSignificantBits()
        };
    }
}
