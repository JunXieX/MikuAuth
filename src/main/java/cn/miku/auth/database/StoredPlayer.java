package cn.miku.auth.database;

import java.util.UUID;

/**
 * 玩家账号记录（数据库行快照，不可变）。
 *
 * <p><b>身份键是 {@code uuid} 而不是昵称</b>：正版账号用 Mojang UUID（改名后不变，
 * 数据自动跟随、旧昵称释放），离线账号用由昵称推导的离线 UUID。
 * 昵称（{@code nicknameLower}）降级为<b>唯一索引</b>，只用于"这个昵称现在归谁"的查找。
 *
 * @param uuid           账号身份：正版 = Mojang UUID，离线 = 离线 UUID
 * @param nickname       当前昵称（保留原始大小写）
 * @param nicknameLower  当前昵称的归一化形式（小写，唯一索引）
 * @param passwordHash   BCrypt 哈希；null 或空 = 未设置密码
 * @param authType       账号类型：PREMIUM / OFFLINE
 * @param registerIp     注册 IP
 * @param registerTime   注册时间戳（毫秒）
 * @param lastLoginIp    最近一次登录 IP
 * @param lastLoginTime  最近一次登录时间戳（毫秒）
 */
public record StoredPlayer(
        UUID uuid,
        String nickname,
        String nicknameLower,
        String passwordHash,
        String authType,
        String registerIp,
        long registerTime,
        String lastLoginIp,
        long lastLoginTime
) {

    /** 验证类型常量：正版账号。 */
    public static final String TYPE_PREMIUM = "PREMIUM";
    /** 验证类型常量：离线（盗版）账号。 */
    public static final String TYPE_OFFLINE = "OFFLINE";

    /** 是否已设置密码。 */
    public boolean hasPassword() {
        return passwordHash != null && !passwordHash.isEmpty();
    }

    /** 是否为正版账号（其 uuid 即 Mojang UUID）。 */
    public boolean isPremiumType() {
        return TYPE_PREMIUM.equals(authType);
    }

    /** 正版账号的 Mojang UUID；离线账号返回 null。 */
    public UUID premiumUuid() {
        return isPremiumType() ? uuid : null;
    }
}
