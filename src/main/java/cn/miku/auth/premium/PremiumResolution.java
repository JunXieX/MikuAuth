package cn.miku.auth.premium;

import java.util.UUID;

/**
 * 单个正版查询源的解析结果。
 *
 * <p>参考 VeloAuth（已获授权使用其代码）的 PremiumResolution 模型，
 * 精简为三种状态：PREMIUM（确认为正版）/ OFFLINE（确认为离线）/ UNKNOWN（无法判定）。
 */
public record PremiumResolution(Status status, UUID uuid, String canonicalName, String source, String message) {

    /** 确认为正版账号。 */
    public static PremiumResolution premium(UUID uuid, String canonicalName, String source) {
        return new PremiumResolution(Status.PREMIUM, uuid, canonicalName, source, null);
    }

    /** 确认为离线（该昵称不存在正版账号）。 */
    public static PremiumResolution offline(String source, String message) {
        return new PremiumResolution(Status.OFFLINE, null, null, source, message);
    }

    /** 无法判定（请求失败、响应异常等）。 */
    public static PremiumResolution unknown(String source, String message) {
        return new PremiumResolution(Status.UNKNOWN, null, null, source, message);
    }

    /**
     * 无法判定，但携带某源给出的 UUID（目前用于"权威源说离线、镜像说正版"的冲突结果）。
     *
     * <p>调用方可用这个 UUID 判断冲突的性质：若它与库中该昵称记录的正版 UUID 一致，
     * 那就是"号主已改名"留下的历史映射，而不是抢注攻击。
     */
    public boolean hasHistoricalUuid() {
        return status == Status.UNKNOWN && uuid != null;
    }

    public boolean isPremium() {
        return status == Status.PREMIUM;
    }

    public boolean isOffline() {
        return status == Status.OFFLINE;
    }

    public boolean isUnknown() {
        return status == Status.UNKNOWN;
    }

    public enum Status {
        PREMIUM,
        OFFLINE,
        UNKNOWN
    }
}
