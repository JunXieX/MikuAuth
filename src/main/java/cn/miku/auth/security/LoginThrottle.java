package cn.miku.auth.security;

import cn.miku.auth.config.MikuConfig;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import org.slf4j.Logger;

/**
 * 跨会话的登录失败计数与临时封禁。
 *
 * <p><b>为什么需要它</b>：{@code login.max-tries} 记在会话对象上（内存、绑定单次连接），
 * 玩家断线重连即清零，暴力破解几乎没有代价。本类把计数做成<b>跨连接</b>的：
 * 同一 IP 或同一账号在窗口期内累计失败达到阈值，即临时拒绝后续尝试。
 *
 * <p><b>为什么放在内存而不是数据库</b>：失败计数是"速率与风控"而非审计数据，
 * 每次密码错误都写库既浪费连接又会在数据库故障时失去保护；重启丢失计数是可接受的
 * （攻击者无法重启代理）。审计需求由日志承担。
 *
 * <p>计数主体有两个维度，任一命中即锁定：
 * <ul>
 *   <li>{@code ip:1.2.3.4} —— 拦"换昵称撞库"；</li>
 *   <li>{@code name:alice} —— 拦"换 IP 撞单账号"。</li>
 * </ul>
 * 触发锁定后计数归零，封禁到期即恢复为"全新若干次尝试"，避免无限续锁。
 */
public final class LoginThrottle {

    /** 锁定信息。 */
    public record Lock(String subject, long remainingMillis) {

        /** 剩余分钟数（向上取整，至少 1）。 */
        public long remainingMinutes() {
            return Math.max(1, (remainingMillis + 59_999L) / 60_000L);
        }
    }

    /** 单个主体的失败计数。 */
    private static final class Counter {
        final AtomicInteger failures = new AtomicInteger();
        volatile long firstFailureAt;
        volatile long lastFailureAt;
        volatile long lockedUntil;
    }

    private final MikuConfig config;
    private final Logger logger;
    /** 时间源：默认取系统时间，测试可注入假时钟以验证封禁到期。 */
    private final java.util.function.LongSupplier clock;
    private final ConcurrentHashMap<String, Counter> counters = new ConcurrentHashMap<>();

    public LoginThrottle(MikuConfig config, Logger logger) {
        this(config, logger, System::currentTimeMillis);
    }

    LoginThrottle(MikuConfig config, Logger logger, java.util.function.LongSupplier clock) {
        this.config = config;
        this.logger = logger;
        this.clock = clock;
    }

    /** 是否启用（阈值 0 表示关闭）。 */
    public boolean enabled() {
        return config.securityMaxFailures() > 0;
    }

    /**
     * 检查是否处于锁定状态。
     *
     * @return null = 可继续尝试；否则为锁定信息
     */
    public Lock check(String ip, String nickname) {
        if (!enabled()) {
            return null;
        }
        long now = clock.getAsLong();
        Lock ipLock = lockOf(subjectIp(ip), now);
        Lock nameLock = lockOf(subjectName(nickname), now);
        if (ipLock == null) {
            return nameLock;
        }
        if (nameLock == null) {
            return ipLock;
        }
        // 两个维度都被锁时，按剩余时间更长的那个告知玩家
        return ipLock.remainingMillis() >= nameLock.remainingMillis() ? ipLock : nameLock;
    }

    /**
     * 记录一次失败；达到阈值时触发锁定。
     *
     * @return 本次是否触发了新的锁定（非 null 表示刚刚锁定）
     */
    public Lock recordFailure(String ip, String nickname) {
        if (!enabled()) {
            return null;
        }
        long now = clock.getAsLong();
        Lock ipLock = bump(subjectIp(ip), now);
        Lock nameLock = bump(subjectName(nickname), now);
        return nameLock != null ? nameLock : ipLock;
    }

    /** 登录成功后清零计数。 */
    /**
     * 认证成功后的计数重置：<b>只清账号维度</b>。
     *
     * <p>IP 维度不能一起清：那等于给攻击者一个"白名单"——用他自己一个有效账号成功登录一次，
     * 就能把该 IP 上"换昵称撞库"的计数清零，IP 维度的保护被反复重置。
     * IP 计数改为随窗口自然过期；确需立刻解除由管理员 {@code /mikuauth unlock <IP>} 显式操作。
     */
    public void reset(String ip, String nickname) {
        if (nickname != null) {
            counters.remove(subjectName(nickname));
        }
    }

    /**
     * 管理员解锁：参数为 IP 时清 IP 维度，否则按账号名清。
     *
     * @return true = 确实存在被清理的计数
     */
    public boolean unlock(String subject) {
        if (subject == null || subject.isEmpty()) {
            return false;
        }
        if (looksLikeIp(subject)) {
            return counters.remove(subjectIp(subject)) != null;
        }
        return counters.remove(subjectName(subject)) != null;
    }

    /** 清理已过期且不再被引用的计数（心跳定期调用）。 */
    public void purge() {
        long now = clock.getAsLong();
        long retain = Math.max(config.securityFailureWindowMinutes(), config.securityLockoutMinutes()) * 60_000L;
        counters.entrySet().removeIf(entry -> {
            Counter counter = entry.getValue();
            return counter.lockedUntil < now && now - counter.lastFailureAt > retain;
        });
    }

    // ---------------------------------------------------------------------
    // 内部
    // ---------------------------------------------------------------------

    private Lock lockOf(String key, long now) {
        Counter counter = counters.get(key);
        if (counter == null || counter.lockedUntil <= now) {
            return null;
        }
        return new Lock(key, counter.lockedUntil - now);
    }

    /** 累加一次失败；返回非 null 表示本次触发了锁定。 */
    private Lock bump(String key, long now) {
        Counter counter = counters.computeIfAbsent(key, ignored -> new Counter());
        int failures;
        synchronized (counter) {
            long windowMillis = config.securityFailureWindowMinutes() * 60_000L;
            // 窗口外的历史失败不再计入
            if (counter.firstFailureAt == 0 || now - counter.firstFailureAt > windowMillis) {
                counter.failures.set(0);
                counter.firstFailureAt = now;
            }
            counter.lastFailureAt = now;
            failures = counter.failures.incrementAndGet();
            if (failures >= config.securityMaxFailures()) {
                long lockoutMillis = config.securityLockoutMinutes() * 60_000L;
                counter.lockedUntil = now + lockoutMillis;
                // 归零：封禁到期后是全新的一轮尝试，避免无限续锁
                counter.failures.set(0);
                counter.firstFailureAt = 0;
                if (logger != null) {
                    logger.warn("[安全] {} 连续登录失败 {} 次，已临时封禁 {} 分钟",
                            key, failures, config.securityLockoutMinutes());
                }
                return new Lock(key, lockoutMillis);
            }
        }
        return null;
    }

    private static String subjectIp(String ip) {
        return "ip:" + (ip == null ? "unknown" : ip);
    }

    private static String subjectName(String nickname) {
        return "name:" + MikuConfig.normalize(nickname == null ? "unknown" : nickname);
    }

    /** 粗略判断参数是 IP 还是玩家名（含 '.' 或 ':' 视为 IPv4/IPv6）。 */
    private static boolean looksLikeIp(String value) {
        return value.indexOf('.') >= 0 || value.indexOf(':') >= 0;
    }
}
