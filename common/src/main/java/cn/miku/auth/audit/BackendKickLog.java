package cn.miku.auth.audit;

import cn.miku.auth.config.MikuConfig;
import cn.miku.auth.util.LogSink;

import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * 后端服务器拒绝进入记录文件。
 *
 * <p><b>为什么需要它</b>：玩家通过认证、准备进入目标服时，可能被目标服（或目标服上的其他插件，
 * 如登录/验证网关、白名单、领地插件）在登录阶段直接踢回。这类拒绝的线索被撕成三片：
 * <ul>
 *   <li>玩家：在认证服里只看到"什么都没发生"，因为踢出动作发生在<b>去往目标服的那条连接</b>上，
 *       而玩家这时还留在认证服；</li>
 *   <li>代理控制台：一行 WARN，只有状态码没有原因；</li>
 *   <li>目标服日志：一行 {@code Disconnecting xxx: 原因}，混在它自己的日志里。</li>
 * </ul>
 * 管理员事后几乎无法还原"谁、什么时候、被哪个服、因为什么进不去"。于是这里把这类事件单独落盘，
 * 与控制台日志分离、不受日志轮转影响。写入机制见 {@link LineFileLog}。
 *
 * <p>原因文本取自代理本身：{@code ConnectionRequestBuilder.Result#getReasonComponent()}，
 * 也就是目标服发出的 Disconnect 包内容，原样保留（换行折叠为 {@code | } 便于逐行查看）。
 */
public final class BackendKickLog {

    /** 单条原因的长度上限：避免把几百行的大段文本整段抄进记录文件。 */
    private static final int MAX_REASON_CHARS = 500;

    private static final DateTimeFormatter TIME_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private static final String HEADER = """
            # MikuAuth 后端拒绝进入记录
            #
            # 记录：玩家已通过认证、但在进入目标服时被该服（或该服上的插件）直接踢回的事件。
            #       原因文本就是目标服给出的踢出原因，原样保留；同一条原因也会转发到玩家聊天栏。
            #
            # 常见原因：未绑定社交账号/未通过验证网关、白名单、封禁、服务器正在重启、人数已满等。
            #           处理方式取决于原因本身——多数需要玩家自己完成；与 MikuAuth 无关。
            #
            # 排查提示：
            #   - 同一条原因反复出现 → 该玩家确实没满足目标服的进入条件，不是网络抖动；
            #   - 目标服日志里的 "Disconnecting <玩家>: <原因>" 是同样的信息，可交叉核对；
            #   - 服务器重启/离线导致的失败不含原因（连接直接断开），不会出现在本文件，
            #     它由转服调度自动重试。
            #
            # 格式：时间 | 玩家 | 目标服 | 原因
            #
            """;

    private final LineFileLog log;

    public BackendKickLog(Path dataDirectory, MikuConfig config, LogSink logger) {
        this.log = new LineFileLog(dataDirectory, config.backendKickLogFile(),
                "backend-kicks.log", HEADER, "[后端拒绝记录]", "MikuAuth-BackendKickLog", logger);
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
     * 记录一次"被后端服务器拒绝进入"。
     *
     * @param nickname 玩家昵称
     * @param server   目标服务器名
     * @param reason   目标服给出的原因（纯文本，可为空）
     */
    public void record(String nickname, String server, String reason) {
        if (!log.enabled()) {
            return;
        }
        log.append(TIME_FORMAT.format(LocalDateTime.now())
                + " | " + nickname
                + " | " + (server == null || server.isEmpty() ? "-" : server)
                + " | " + shorten(reason)
                + System.lineSeparator(), nickname);
    }

    /** 折叠换行并截断过长的原因（目标服有时会给出整段说明）。 */
    private static String shorten(String reason) {
        if (reason == null || reason.isBlank()) {
            return "（目标服未提供原因）";
        }
        String flat = reason.replaceAll("\\R+", " | ").trim();
        return flat.length() <= MAX_REASON_CHARS
                ? flat
                : flat.substring(0, MAX_REASON_CHARS) + "…（已截断）";
    }
}
