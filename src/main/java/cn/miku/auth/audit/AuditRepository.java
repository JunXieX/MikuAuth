package cn.miku.auth.audit;

import java.util.List;
import java.util.concurrent.CompletableFuture;

/**
 * 审计日志存储契约。
 *
 * <p>与 {@link cn.miku.auth.database.AuthRepository} 分开：审计是旁路关注点，
 * 既不应让账号状态机依赖它，也不该让"记录日志失败"影响认证流程。
 * 具体实现见 {@link cn.miku.auth.database.DatabaseManager}。
 */
public interface AuditRepository {

    /** 追加一条记录。 */
    CompletableFuture<Void> appendAudit(AuditEntry entry);

    /** 按昵称查询最近若干条（时间倒序）。 */
    CompletableFuture<List<AuditEntry>> findAuditByNickname(String nickname, int limit);

    /** 按 IP 查询最近若干条（时间倒序）。 */
    CompletableFuture<List<AuditEntry>> findAuditByIp(String ip, int limit);

    /** 删除早于指定时间的记录，返回删除条数。 */
    CompletableFuture<Integer> purgeExpiredAudit(long beforeMillis);
}
