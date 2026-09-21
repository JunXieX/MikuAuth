package cn.miku.auth.audit;

import cn.miku.auth.config.MikuConfig;
import org.slf4j.Logger;

import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 登录审计记录器。
 *
 * <p>设计要点：
 * <ul>
 *   <li><b>旁路</b>：记录失败只打 WARN，绝不抛出、绝不阻塞、绝不影响认证结果
 *       （审计是观测手段，不能成为新的故障点）；</li>
 *   <li><b>异步</b>：写入经数据库执行器排队，事件线程只做一次入队；</li>
 *   <li><b>可关闭</b>：{@code audit.enabled} 关闭后所有记录调用立即返回，
 *       连字符串拼接都不做（下面每处调用都用 {@link #enabled()} 前置判断）；</li>
 *   <li><b>自动过期</b>：由心跳周期调用 {@link #purgeExpired()} 按保留天数清理。</li>
 * </ul>
 */
public final class AuditLogger {

    private final AuditRepository repository;
    private final MikuConfig config;
    private final Logger logger;

    /**
     * 失败类事件的合并窗口：账号+IP → 最近一条的写入时刻。
     *
     * <p>暴破时每一次密码错误都会产生一条 {@code LOGIN_FAIL}，若全部落库，
     * 单机即可在数十秒内把审计表写满、并把数据库工作线程排队塞满
     * （SQLite 只有 1 个线程）。这里对同一账号+IP 在窗口内的重复失败<b>只留一条</b>。
     * {@code REJECT_IP_LIMIT} 同理：注册被 IP 配额拦下时玩家可以反复提交，
     * 不合并同样会刷爆审计表。
     *
     * <p>取舍：牺牲了"逐次失败"的明细，但安全能力不受影响——
     * 次数统计与临时封禁由 {@link cn.miku.auth.security.LoginThrottle} 独立完成，
     * 审计只用于事后回溯"谁在什么时候被拒过"。
     */
    private final ConcurrentHashMap<String, Long> recentFailures = new ConcurrentHashMap<>();

    /** 需要合并的失败类事件：同一账号+IP 在窗口内只留第一条。 */
    private static final Set<AuditAction> MERGEABLE_ACTIONS =
            Set.of(AuditAction.LOGIN_FAIL, AuditAction.REJECT_IP_LIMIT);

    /** 失败事件合并窗口（毫秒）。 */
    private static final long FAILURE_MERGE_WINDOW_MILLIS = 60_000L;

    /** 合并窗口表的上限，超出即清理过期项（防止长期运行缓慢增长）。 */
    private static final int MERGE_TABLE_LIMIT = 4096;

    public AuditLogger(AuditRepository repository, MikuConfig config, Logger logger) {
        this.repository = repository;
        this.config = config;
        this.logger = logger;
    }

    /** 审计是否启用（调用方应据此跳过参数组装）。 */
    public boolean enabled() {
        return config.auditEnabled();
    }

    /**
     * 记录一条审计事件。
     *
     * @param detail 可为 null；建议给出可读的补充说明（失败原因、认证方式等）
     */
    public void record(AuditAction action, String nickname, UUID uuid, String ip, String detail) {
        if (!enabled()) {
            return;
        }
        if (MERGEABLE_ACTIONS.contains(action) && withinMergeWindow(nickname, ip)) {
            return; // 窗口内已记过该账号+IP 的失败，避免暴破/反复提交刷爆审计表
        }
        try {
            repository.appendAudit(AuditEntry.of(nickname, uuid, ip, action, detail))
                    .exceptionally(throwable -> {
                        logger.warn("[审计] 写入失败（不影响认证流程）: {}", throwable.toString());
                        return null;
                    });
        } catch (Throwable t) {
            logger.warn("[审计] 提交失败（不影响认证流程）: {}", t.toString());
        }
    }

    /** 是否处于失败合并窗口内（同账号+同 IP 的重复失败）。 */
    private boolean withinMergeWindow(String nickname, String ip) {
        String key = MikuConfig.normalize(nickname) + "|" + (ip == null ? "-" : ip);
        long now = System.currentTimeMillis();
        Long previous = recentFailures.put(key, now);
        if (recentFailures.size() > MERGE_TABLE_LIMIT) {
            recentFailures.entrySet().removeIf(entry -> now - entry.getValue() > FAILURE_MERGE_WINDOW_MILLIS);
        }
        return previous != null && now - previous < FAILURE_MERGE_WINDOW_MILLIS;
    }

    /** 按保留天数清理历史记录。 */
    public void purgeExpired() {
        if (!enabled()) {
            return;
        }
        long retainDays = config.auditRetainDays();
        if (retainDays <= 0) {
            return; // 0 = 永久保留
        }
        long cutoff = System.currentTimeMillis() - retainDays * 24L * 60 * 60 * 1000;
        try {
            repository.purgeExpiredAudit(cutoff).exceptionally(throwable -> {
                logger.warn("[审计] 清理失败: {}", throwable.toString());
                return null;
            });
        } catch (Throwable t) {
            logger.warn("[审计] 清理提交失败: {}", t.toString());
        }
    }
}
