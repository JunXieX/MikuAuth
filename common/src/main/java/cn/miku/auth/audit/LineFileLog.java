package cn.miku.auth.audit;

import cn.miku.auth.util.LogSink;
import cn.miku.auth.util.PathSafety;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/**
 * 单文件追加日志：旁路记录"事后要能翻出来"的事件（昵称冲突、后端拒绝）。
 *
 * <p>{@link PremiumConflictLog} 与 {@link BackendKickLog} 只差文件头与行格式，写入机制完全相同：
 * 单线程 + 有界队列（事件线程绝不做磁盘 IO）、首次写入补文件头、超过 5MB 轮转为 {@code .1}、
 * 关服排空队列。这段机制只保留一份，避免两个文件各自演化。
 *
 * <p>写入失败只记 WARN：记录是观测手段，不能成为认证/转服流程的新故障点。
 */
final class LineFileLog {

    /** 单文件上限（超过即轮转为 .1）。 */
    private static final long MAX_BYTES = 5L * 1024 * 1024;
    /** 写盘队列上限：写不动时宁可丢记录，也不拖慢事件线程。 */
    private static final int QUEUE_CAPACITY = 512;

    /** 目标文件；null = 未启用。 */
    private final Path file;
    /** 首次写入时写在文件最前面的说明（含成因与处理方式）。 */
    private final String header;
    /** 日志前缀，如 {@code [正版冲突记录]}。 */
    private final String tag;
    private final LogSink logger;
    /** 写盘线程；未启用时为 null（不为关闭的记录器白开线程）。 */
    private final ExecutorService writer;

    LineFileLog(Path dataDirectory, String configuredName, String fallbackName,
                String header, String tag, String threadName, LogSink logger) {
        this.logger = logger;
        this.header = header;
        this.tag = tag;
        this.file = configuredName == null || configuredName.isBlank()
                ? null
                : PathSafety.resolveInside(dataDirectory, configuredName, fallbackName, logger);
        this.writer = file == null ? null : newWriter(threadName);
    }

    private static ExecutorService newWriter(String threadName) {
        return new ThreadPoolExecutor(1, 1, 0L, TimeUnit.MILLISECONDS,
                new LinkedBlockingQueue<>(QUEUE_CAPACITY),
                runnable -> {
                    Thread thread = new Thread(runnable, threadName);
                    thread.setDaemon(true);
                    return thread;
                },
                new ThreadPoolExecutor.AbortPolicy());
    }

    boolean enabled() {
        return file != null;
    }

    Path file() {
        return file;
    }

    /**
     * 入队一行（调用方负责拼好完整的行，含行尾换行）。
     *
     * @param subject 出问题时用于指认"丢的是谁的那条记录"（昵称等）
     */
    void append(String line, String subject) {
        if (writer == null) {
            return;
        }
        try {
            writer.execute(() -> writeLine(line));
        } catch (RejectedExecutionException e) {
            logger.warn("{} 写入队列已满，丢弃一条 {} 的记录（插件关闭中或磁盘过慢）", tag, subject);
        }
    }

    /** 等待已入队的行全部落盘（测试与关服时使用）。 */
    void flush() {
        // 已经在 shutdown 之后（例如关服流程跑过一遍又有人来 flush）：没有队列可等，
        // 直接返回，别用"超时"这种与真因不符的文案误导排障
        if (writer == null || writer.isShutdown()) {
            return;
        }
        try {
            writer.submit(() -> {
            }).get(3, TimeUnit.SECONDS);
        } catch (Exception e) {
            logger.warn("{} 等待落盘超时: {}", tag, e.toString());
        }
    }

    /** 插件关闭时调用：等待队列排空，避免丢掉最后几条记录。 */
    void shutdown() {
        if (writer == null) {
            return;
        }
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

    /** 实际写盘；只在单线程写盘器内执行，因此无需额外同步。 */
    private void writeLine(String line) {
        try {
            Path parent = file.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            rotateIfNeeded();
            boolean fresh = !Files.exists(file) || Files.size(file) == 0L;
            Files.writeString(file, fresh ? header + line : line,
                    StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (Throwable t) {
            logger.warn("{} 写入 {} 失败: {}", tag, file, t.toString());
        }
    }

    /** 超过上限时把当前文件改名为 .1（只保留一份历史）。 */
    private void rotateIfNeeded() throws IOException {
        if (!Files.exists(file) || Files.size(file) <= MAX_BYTES) {
            return;
        }
        Path rotated = file.resolveSibling(file.getFileName() + ".1");
        Files.move(file, rotated, StandardCopyOption.REPLACE_EXISTING);
        logger.info("{} 文件超过 {} MB，已轮转为 {}", tag, MAX_BYTES / 1024 / 1024, rotated.getFileName());
    }
}
