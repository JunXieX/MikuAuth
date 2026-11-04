package cn.miku.auth.log;

import cn.miku.auth.util.LogSink;
import org.slf4j.Logger;

/**
 * 把代理端的 slf4j 日志接到公共层的 {@link LogSink}。
 *
 * <p>公共层（{@code :common}）被代理端与纸端共用，不能写死任何日志门面，
 * 因此两端各提供一个适配器：这边用 slf4j（与代理日志系统同源），纸端用
 * {@code java.util.logging}。
 */
public final class Slf4jLogSink implements LogSink {

    private final Logger logger;

    private Slf4jLogSink(Logger logger) {
        this.logger = logger;
    }

    public static LogSink of(Logger logger) {
        return logger == null ? LogSink.none() : new Slf4jLogSink(logger);
    }

    @Override
    public void info(String format, Object... args) {
        if (logger.isInfoEnabled()) {
            logger.info(format, args);
        }
    }

    @Override
    public void warn(String format, Object... args) {
        if (logger.isWarnEnabled()) {
            logger.warn(format, args);
        }
    }

    @Override
    public void error(String format, Object... args) {
        if (logger.isErrorEnabled()) {
            logger.error(format, args);
        }
    }

    @Override
    public void debug(String format, Object... args) {
        if (logger.isDebugEnabled()) {
            logger.debug(format, args);
        }
    }

    @Override
    public void error(String message, Throwable throwable) {
        logger.error(message, throwable);
    }
}
