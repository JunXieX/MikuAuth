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
 * 2026-09-22 之前本文件按"任意进服失败都算昵称冲突"写入，实测 16 条记录全部是误报，已修正。
 *
 * <p><b>为什么仍然单独落盘</b>：与控制台日志分离，不受日志轮转影响，
 * 便于管理员在没有在线的时间里事后核对"谁在什么时候、从哪个 IP 因同名冲突被顶下线"。
 *
 * <p>设计要点：
 * <ul>
 *   <li><b>旁路</b>：写入失败只记 WARN，绝不影响认证流程；</li>
 *   <li><b>线程安全</b>：事件可能来自不同 Netty 线程，写入串行化；</li>
 *   <li><b>自动轮转</b>：超过 5MB 时把旧文件改名为 {@code .1}，避免无限增长；</li>
 *   <li><b>首行说明</b>：文件头部写明成因与处理方式，日后翻看无需查代码。</li>
 * </ul>
 */
public final class PremiumConflictLog {

    /** 单文件上限（超过即轮转为 .1）。 */
    private static final long MAX_BYTES = 5L * 1024 * 1024;

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

    /** 目标文件；null 表示未启用。 */
    private final Path file;
    private final Logger logger;

    /**
     * 写盘线程池：单线程 + 有界队列。
     *
     * <p>调用方是 Netty 事件线程（{@code DisconnectEvent}），**绝不能在事件线程上做磁盘 IO**：
     * 多条冲突事件同时到达时会串行阻塞事件线程，殃及所有玩家的断线处理。
     * 因此这里改为入队后立即返回。队列满时直接拒绝并记 WARN——
     * 记录是观测手段，宁可丢一条日志也不能拖慢事件线程。
     */
    private final ExecutorService writer;

    /** 写盘队列上限。 */
    private static final int QUEUE_CAPACITY = 512;

    public PremiumConflictLog(Path dataDirectory, MikuConfig config, Logger logger) {
        this.logger = logger;
        String configured = config.premiumConflictLogFile();
        this.file = configured == null || configured.isBlank()
                ? null
                : dataDirectory.resolve(configured.trim());
        this.writer = new ThreadPoolExecutor(1, 1, 0L, TimeUnit.MILLISECONDS,
                new LinkedBlockingQueue<>(QUEUE_CAPACITY),
                runnable -> {
                    Thread thread = new Thread(runnable, "MikuAuth-ConflictLog");
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
            logger.warn("[正版冲突记录] 等待落盘超时: {}", e.toString());
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
     * 记录一次"因同名冲突被顶下线"的事件。
     *
     * @param nickname 玩家使用的昵称
     * @param ip       来源 IP（可能为 null）
     * @param status   断开状态的中文描述
     * @param detail   补充说明（例如该昵称的判定来源）
     */
    public void record(String nickname, String ip, String status, String detail) {
        if (file == null) {
            return;
        }
        String line = TIME_FORMAT.format(LocalDateTime.now())
                + " | " + nickname
                + " | " + (ip == null || ip.isEmpty() ? "-" : ip)
                + " | " + status
                + " | " + detail
                + System.lineSeparator();
        try {
            // 事件线程只做入队，磁盘 IO 交给写盘线程
            writer.execute(() -> writeLine(line));
        } catch (RejectedExecutionException e) {
            logger.warn("[正版冲突记录] 写入队列已满，丢弃一条 {} 的记录（插件关闭中或磁盘过慢）", nickname);
        }
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
            // 记录失败绝不能影响认证流程
            logger.warn("[正版冲突记录] 写入 {} 失败: {}", file, t.toString());
        }
    }

    /** 超过上限时把当前文件改名为 .1（只保留一份历史）。 */
    private void rotateIfNeeded() throws IOException {
        if (!Files.exists(file) || Files.size(file) <= MAX_BYTES) {
            return;
        }
        Path rotated = file.resolveSibling(file.getFileName() + ".1");
        Files.move(file, rotated, StandardCopyOption.REPLACE_EXISTING);
        logger.info("[正版冲突记录] 文件超过 {} MB，已轮转为 {}", MAX_BYTES / 1024 / 1024, rotated.getFileName());
    }
}
