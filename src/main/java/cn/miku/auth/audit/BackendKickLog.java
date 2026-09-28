package cn.miku.auth.audit;

import cn.miku.auth.config.MikuConfig;
import org.slf4j.Logger;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

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
 * 与控制台日志分离、不受日志轮转影响。
 *
 * <p>原因文本取自代理本身：{@code ConnectionRequestBuilder.Result#getReasonComponent()}，
 * 也就是目标服发出的 Disconnect 包内容，原样保留（换行折叠为 {@code | } 便于逐行查看）。
 *
 * <p>设计要点（与 {@link PremiumConflictLog} 同一套）：
 * <ul>
 *   <li><b>旁路</b>：写入失败只记 WARN，绝不影响认证/转服流程；</li>
 *   <li><b>线程安全</b>：事件可能来自不同线程，写入串行化；</li>
 *   <li><b>自动轮转</b>：超过 5MB 时把旧文件改名为 {@code .1}，避免无限增长；</li>
 *   <li><b>首行说明</b>：文件头部写明成因与处理方式，日后翻看无需查代码。</li>
 * </ul>
 */
public final class BackendKickLog {

    /** 单文件上限（超过即轮转为 .1）。 */
    private static final long MAX_BYTES = 5L * 1024 * 1024;

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

    /** 目标文件；null 表示未启用。 */
    private final Path file;
    private final Logger logger;

    /**
     * 写盘线程池：单线程 + 有界队列。
     *
     * <p>调用方在连接请求的回调线程上，绝不做磁盘 IO；队列满时直接拒绝并记 WARN——
     * 记录是观测手段，不能拖慢转服流程。
     */
    private final ExecutorService writer;

    private static final int QUEUE_CAPACITY = 512;

    public BackendKickLog(Path dataDirectory, MikuConfig config, Logger logger) {
        this.logger = logger;
        String configured = config.backendKickLogFile();
        // 文件名落地前先做越界检查：否则 "..\..\server.properties" 之类的配置值
        // 会让记录内容被追加到数据目录之外的文件里
        this.file = configured == null || configured.isBlank()
                ? null
                : cn.miku.auth.util.PathSafety.resolveInside(
                        dataDirectory, configured, "backend-kicks.log", logger);
        this.writer = new ThreadPoolExecutor(1, 1, 0L, TimeUnit.MILLISECONDS,
                new LinkedBlockingQueue<>(QUEUE_CAPACITY),
                runnable -> {
                    Thread thread = new Thread(runnable, "MikuAuth-BackendKickLog");
                    thread.setDaemon(true);
                    return thread;
                },
                new ThreadPoolExecutor.AbortPolicy());
    }

    /** 插件关闭时调用：等待队列排空，避免丢掉最后几条记录。 */
    public void shutdown() {
        writer.shutdown();
        try {
            if (!writer.awaitTermination(3, TimeUnit.SECONDS)) {
                writer.shutdownNow();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            writer.shutdownNow();
        }
    }

    /** 等待已入队的记录全部落盘（测试与关服时使用）。 */
    public void flush() {
        try {
            writer.submit(() -> {
            }).get(3, TimeUnit.SECONDS);
        } catch (Exception e) {
            logger.warn("[后端拒绝记录] 等待落盘超时: {}", e.toString());
        }
    }

    /** 是否启用（配置为空则关闭）。 */
    public boolean enabled() {
        return file != null;
    }

    /** 记录文件路径（诊断/启动日志用）。 */
    public Path file() {
        return file;
    }

    /**
     * 记录一次"被后端服务器拒绝进入"。
     *
     * @param nickname 玩家昵称
     * @param server   目标服务器名
     * @param reason   目标服给出的原因（纯文本，可为空）
     */
    public void record(String nickname, String server, String reason) {
        if (file == null) {
            return;
        }
        String line = TIME_FORMAT.format(LocalDateTime.now())
                + " | " + nickname
                + " | " + (server == null || server.isEmpty() ? "-" : server)
                + " | " + shorten(reason)
                + System.lineSeparator();
        try {
            writer.execute(() -> writeLine(line));
        } catch (RejectedExecutionException e) {
            logger.warn("[后端拒绝记录] 写入队列已满，丢弃一条 {} 的记录（插件关闭中或磁盘过慢）", nickname);
        }
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

    /** 实际写盘；只在单线程写盘器内执行，因此无需额外同步。 */
    private void writeLine(String line) {
        try {
            Path parent = file.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            rotateIfNeeded();
            boolean fresh = !Files.exists(file) || Files.size(file) == 0L;
            Files.writeString(file, fresh ? HEADER + line : line,
                    StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (Throwable t) {
            logger.warn("[后端拒绝记录] 写入 {} 失败: {}", file, t.toString());
        }
    }

    /** 超过上限时把当前文件改名为 .1（只保留一份历史）。 */
    private void rotateIfNeeded() throws IOException {
        if (!Files.exists(file) || Files.size(file) <= MAX_BYTES) {
            return;
        }
        Path rotated = file.resolveSibling(file.getFileName() + ".1");
        Files.move(file, rotated, StandardCopyOption.REPLACE_EXISTING);
        logger.info("[后端拒绝记录] 文件超过 {} MB，已轮转为 {}", MAX_BYTES / 1024 / 1024,
                rotated.getFileName());
    }
}
