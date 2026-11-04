package cn.miku.auth.paper;

import cn.miku.auth.util.LogSink;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * 把纸端的 {@code java.util.logging} 接到公共层的 {@link LogSink}。
 *
 * <p>公共层不认识任何日志库；代理端用 slf4j 适配（{@code Slf4jLogSink}），纸端用这个。
 */
final class JulLogSink implements LogSink {

    private final Logger logger;

    private JulLogSink(Logger logger) {
        this.logger = logger;
    }

    static LogSink of(Logger logger) {
        return logger == null ? LogSink.none() : new JulLogSink(logger);
    }

    @Override
    public void info(String format, Object... args) {
        logger.log(Level.INFO, LogSink.format(format, args));
    }

    @Override
    public void warn(String format, Object... args) {
        logger.log(Level.WARNING, LogSink.format(format, args));
    }

    @Override
    public void error(String format, Object... args) {
        logger.log(Level.SEVERE, LogSink.format(format, args));
    }

    @Override
    public void debug(String format, Object... args) {
        logger.log(Level.FINE, LogSink.format(format, args));
    }

    @Override
    public void error(String message, Throwable throwable) {
        logger.log(Level.SEVERE, message, throwable);
    }
}
