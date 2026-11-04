package cn.miku.auth.paper;

import java.util.concurrent.ConcurrentHashMap;

/**
 * 跨连接的登录失败计数与临时封禁。
 *
 * <p>{@code login.max-tries} 只限制"单次连接"内的尝试次数，玩家断线重连就清零；
 * 这里把计数做成跨连接的：同一 IP 与同一账号分别累计，任一维度达到阈值即临时拒绝。
 *
 * <p>放在内存而不是数据库：失败计数属于速率风控，重启清零可以接受（攻击者无法重启服务器），
 * 审计留痕由 {@code miku_audit_log} 负责。
 */
final class Throttle {

    /** 一个被判定的锁。 */
    record Lock(String subject, long remainingMillis) {
        long minutes() {
            return Math.max(1, (remainingMillis + 59_999L) / 60_000L);
        }
    }

    private static final class Counter {
        int failures;
        long firstAt;
        long lastAt;
        long lockedUntil;
    }

    private final PaperConfig config;
    private final ConcurrentHashMap<String, Counter> counters = new ConcurrentHashMap<>();

    Throttle(PaperConfig config) {
        this.config = config;
    }

    private boolean enabled() {
        return config.securityMaxFailures() > 0;
    }

    /** 是否已被封禁；null 表示可以继续尝试。 */
    Lock check(String ip, String nickname) {
        if (!enabled()) {
            return null;
        }
        long now = System.currentTimeMillis();
        Lock byIp = lockOf("ip:" + (ip == null ? "unknown" : ip), now);
        Lock byName = lockOf("name:" + (nickname == null ? "unknown" : nickname.toLowerCase(java.util.Locale.ROOT)), now);
        if (byIp == null) {
            return byName;
        }
        if (byName == null) {
            return byIp;
        }
        return byIp.remainingMillis() >= byName.remainingMillis() ? byIp : byName;
    }

    /** 记录一次失败；返回非 null 表示本次刚好触发封禁。 */
    Lock recordFailure(String ip, String nickname) {
        if (!enabled()) {
            return null;
        }
        long now = System.currentTimeMillis();
        Lock byIp = bump("ip:" + (ip == null ? "unknown" : ip), now);
        Lock byName = bump("name:" + (nickname == null ? "unknown" : nickname.toLowerCase(java.util.Locale.ROOT)), now);
        return byName != null ? byName : byIp;
    }

    /** 认证成功后只清账号维度：清 IP 维度等于给攻击者一个"用自己号登录一次就洗白"的后门。 */
    void reset(String nickname) {
        if (nickname != null) {
            counters.remove("name:" + nickname.toLowerCase(java.util.Locale.ROOT));
        }
    }

    /** 管理员解锁：含点号或冒号按 IP 处理，否则按账号。 */
    boolean unlock(String subject) {
        if (subject == null || subject.isBlank()) {
            return false;
        }
        String key = subject.indexOf('.') >= 0 || subject.indexOf(':') >= 0
                ? "ip:" + subject
                : "name:" + subject.toLowerCase(java.util.Locale.ROOT);
        return counters.remove(key) != null;
    }

    /** 心跳式清理：窗口外且未在封禁中的条目直接丢弃。 */
    void purge() {
        long now = System.currentTimeMillis();
        long retain = Math.max(config.securityWindowMinutes(), config.securityLockoutMinutes()) * 60_000L;
        counters.entrySet().removeIf(entry -> {
            Counter counter = entry.getValue();
            return counter.lockedUntil < now && now - counter.lastAt > retain;
        });
    }

    private Lock lockOf(String key, long now) {
        Counter counter = counters.get(key);
        if (counter == null || counter.lockedUntil <= now) {
            return null;
        }
        return new Lock(key, counter.lockedUntil - now);
    }

    private Lock bump(String key, long now) {
        Counter counter = counters.computeIfAbsent(key, ignored -> new Counter());
        synchronized (counter) {
            long window = config.securityWindowMinutes() * 60_000L;
            if (counter.firstAt == 0 || now - counter.firstAt > window) {
                counter.failures = 0;
                counter.firstAt = now;
            }
            counter.lastAt = now;
            counter.failures++;
            if (counter.failures >= config.securityMaxFailures()) {
                long lockout = config.securityLockoutMinutes() * 60_000L;
                counter.lockedUntil = now + lockout;
                counter.failures = 0;
                counter.firstAt = 0;
                return new Lock(key, lockout);
            }
        }
        return null;
    }
}
