package cn.miku.auth.premium;

import java.util.UUID;

/**
 * 单个正版查询源的解析结果。
 *
 * <p>参考 VeloAuth（已获授权使用其代码）的 PremiumResolution 模型，
 * 精简为三种状态：PREMIUM（确认为正版）/ OFFLINE（确认为离线）/ UNKNOWN（无法判定）。
 *
 * <p><b>权威性（{@link #authoritative()}）不可省略</b>：Mojang 官方 API 说"这个昵称没有正版账号"
 * 与镜像站说同样的话，可信度完全不同 —— 镜像数据存在滞后（玩家刚改名、刚注册），
 * 而"按离线处理"会进一步触发<b>清理数据库中该昵称的正版记录</b>。
 * 2026-09-22 的修复起因正是：Mojang 不可用（UNKNOWN）+ 镜像返回 404，
 * 被当成权威结论而删掉了真号主的记录，随后昵称可被离线客户端抢注。
 * 因此：<b>只有权威源结论才允许驱动破坏性动作与负缓存</b>。
 */
public record PremiumResolution(Status status, UUID uuid, String canonicalName, String source,
                                String message, boolean authoritative) {

    /** 确认为正版账号。 */
    public static PremiumResolution premium(UUID uuid, String canonicalName, String source,
                                            boolean authoritative) {
        return new PremiumResolution(Status.PREMIUM, uuid, canonicalName, source, null, authoritative);
    }

    /** 确认为正版账号（默认非权威：仅镜像源会用到）。 */
    public static PremiumResolution premium(UUID uuid, String canonicalName, String source) {
        return premium(uuid, canonicalName, source, false);
    }

    /** 确认为离线（该昵称不存在正版账号）。 */
    public static PremiumResolution offline(String source, String message, boolean authoritative) {
        return new PremiumResolution(Status.OFFLINE, null, null, source, message, authoritative);
    }

    /** 确认为离线（默认非权威：仅镜像源会用到）。 */
    public static PremiumResolution offline(String source, String message) {
        return offline(source, message, false);
    }

    /** 无法判定（请求失败、响应异常等）。 */
    public static PremiumResolution unknown(String source, String message) {
        return new PremiumResolution(Status.UNKNOWN, null, null, source, message, false);
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

    /**
     * 结论是否来自<b>权威源</b>（Mojang 官方 API）。
     *
     * <p>调用方必须据此决定"能不能做破坏性动作"：只有权威结论才允许清理
     * 数据库里的正版记录、才允许做负缓存。镜像源的 OFFLINE 可能只是数据滞后。
     */
    public boolean isAuthoritative() {
        return authoritative;
    }

    public enum Status {
        PREMIUM,
        OFFLINE,
        UNKNOWN
    }
}
