package cn.miku.auth.audit;

import java.util.UUID;

/**
 * 一条审计记录。
 *
 * @param id        自增主键（查询结果用；写入时忽略）
 * @param nickname  玩家展示昵称
 * @param uuid      账号 UUID（可能为 null：连接在分配 UUID 前就被拒绝）
 * @param ip        来源 IP（可能为 null：取不到地址的极端情况）
 * @param action    事件类型
 * @param detail    补充说明（失败原因、认证方式、管理员操作内容等）
 * @param createdAt 事件时间（毫秒时间戳）
 */
public record AuditEntry(long id, String nickname, UUID uuid, String ip,
                         AuditAction action, String detail, long createdAt) {

    /** 构造待写入的记录（id 由数据库生成）。 */
    public static AuditEntry of(String nickname, UUID uuid, String ip,
                                AuditAction action, String detail) {
        return new AuditEntry(0L, nickname, uuid, ip, action, detail, System.currentTimeMillis());
    }
}
