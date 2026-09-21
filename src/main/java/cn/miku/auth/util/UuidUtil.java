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

    /** 解析存储的 UUID 字符串；null/空/非法一律返回 null。 */
    public static UUID parse(String text) {
        if (text == null || text.isBlank()) {
            return null;
        }
        try {
            return UUID.fromString(text.trim());
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /** 统一的存储格式：小写带连字符（{@link UUID#toString()} 即此格式）。 */
    public static String format(UUID uuid) {
        return uuid == null ? null : uuid.toString();
    }
}
