package cn.miku.auth.audit;

import cn.miku.auth.config.MikuConfig;
import cn.miku.auth.util.LogSink;

import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * 昵称冲突记录文件。
 *
 * <p><b>记录什么</b>：同名连接已经在线、本次连接被顶下线的事件
 * （{@code DisconnectEvent} 状态为「同名冲突」，即 {@code CONFLICTING_LOGIN}）。
 * 这类事件在代理启用"顶号"行为时才会出现，其余登录失败都另有更准确的落点
 * （控制台日志 / {@code /mikuauth diagnose}）。
 *
 * <p><b>不记录什么（重要）</b>：玩家使用"已属于正版账号的昵称"却以<b>离线客户端</b>连接时，
 * 会话校验失败发生在加密握手阶段，而 Velocity 只在 {@code LoginEvent} 触发之后才构造
 * {@code DisconnectEvent}（详见 {@code AuthManager#logJoinFailure} 的说明），
 * 因此<b>这类失败不产生任何事件，也不会出现在本文件里</b> ——
 * 玩家只会看到客户端原生的「无效会话（Invalid session）」，
 * 服务端侧的线索在代理控制台（hasJoined 校验失败）与 {@code /mikuauth diagnose} 里。
 *
 * <p><b>为什么仍然单独落盘</b>：与控制台日志分离，不受日志轮转影响，
 * 便于管理员在没有在线的时间里事后核对"谁在什么时候、从哪个 IP 因同名冲突被顶下线"。
 * 写入机制（异步入队、文件头、轮转、关服排空）见 {@link LineFileLog}。
 */
public final class PremiumConflictLog {

    private static final DateTimeFormatter TIME_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private static final String HEADER = """
            # MikuAuth 昵称冲突记录
            #
            # 记录：同名连接已在线、本次连接被顶下线的事件（代理的「重复登录冲突」）。
            #
            # 注意：玩家使用「已属于正版账号的昵称」但以离线客户端连接时，失败发生在加密握手阶段，
            #       该阶段 Velocity 不产生任何事件（DisconnectEvent 只在登录事件触发之后才发出），
            #       所以这类失败不会出现在本文件里 —— 玩家在客户端看到原生「无效会话」，
            #       代理控制台会留下 hasJoined 校验失败的记录，排查以控制台日志为准。
            #
            # 处理方式：
            #   1) 该昵称仍属于某个正版账号 → 让玩家改用正版启动器登录，或更换昵称；
            #   2) 该昵称已不被任何正版账号使用（玩家在 Mojang 改名后遗留、记录过期）
            #      → 才可执行 /mikuauth unbind <昵称> 清除绑定。
            #      切勿对仍有正版账号持有的昵称执行 unbind，否则等于开放该昵称给任何人。
            #
            # 详情可用 /mikuauth diagnose <昵称> 回放完整判定链路。
            # 格式：时间 | 昵称 | 来源 IP | 断开状态 | 说明
            #
            """;

    private final LineFileLog log;

    public PremiumConflictLog(Path dataDirectory, MikuConfig config, LogSink logger) {
        this.log = new LineFileLog(dataDirectory, config.premiumConflictLogFile(),
                "premium-conflicts.log", HEADER, "[正版冲突记录]", "MikuAuth-ConflictLog", logger);
    }

    /** 插件关闭时调用：等待队列排空，避免丢掉最后几条记录。 */
    public void shutdown() {
        log.shutdown();
    }

    /** 等待已入队的记录全部落盘（测试与关服时使用）。 */
    public void flush() {
        log.flush();
    }

    /** 是否启用（配置为空则关闭）。 */
    public boolean enabled() {
        return log.enabled();
    }

    /** 记录文件路径（诊断/启动日志用）。 */
    public Path file() {
        return log.file();
    }

    /**
     * 记录一次"因同名冲突被顶下线"的事件。
     *
     * @param nickname 玩家使用的昵称
     * @param ip       来源 IP（可能为 null）
     * @param status   断开状态的中文描述
     * @param detail   补充说明（例如该昵称的判定来源）
     */
    public void record(String nickname, String ip, String status, String detail) {
        if (!log.enabled()) {
            return;
        }
        log.append(TIME_FORMAT.format(LocalDateTime.now())
                + " | " + nickname
                + " | " + (ip == null || ip.isEmpty() ? "-" : ip)
                + " | " + status
                + " | " + detail
                + System.lineSeparator(), nickname);
    }
}
