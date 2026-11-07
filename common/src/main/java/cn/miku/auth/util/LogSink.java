package cn.miku.auth.util;

/**
 * 平台无关的日志出口。
 *
 * <p><b>为什么不让公共层直接用 slf4j</b>：公共层同时被代理端（Velocity，运行期有 slf4j）与
 * 纸端（Paper，只有 {@code java.util.logging}）使用。公共层一旦写死某个日志门面，另一端就得
 * 为了它额外携带一份实现，或者把整块代码排除在共用之外。这里只定义一个最小接口，
 * 两端各给一个实现，公共层不认识任何日志库。
 *
 * <p><b>调用风格与 slf4j 一致</b>：{@code {} } 占位符，最后一个参数是 {@link Throwable} 时打印堆栈。
 * 这样历史代码从 slf4j 迁移过来时调用点无需改写。
 */
public interface LogSink {

    void info(String format, Object... args);

    void warn(String format, Object... args);

    void error(String format, Object... args);

    void debug(String format, Object... args);

    /** 带堆栈的错误日志；比 varargs 版本更精确，因此 {@code error("...", e)} 会命中这里。 */
    void error(String message, Throwable throwable);

    /** 什么都不做（单元测试与"日志被显式关闭"的场景）。 */
    static LogSink none() {
        return Noop.INSTANCE;
    }

    /** slf4j 风格的 {@code {} } 占位符替换；参数不足时保留占位符原样，避免再抛一次异常。 */
    static String format(String format, Object... args) {
        if (format == null) {
            return "null";
        }
        if (args == null || args.length == 0 || format.indexOf("{}") < 0) {
            return format;
        }
        StringBuilder out = new StringBuilder(format.length() + 32);
        int argIndex = 0;
        int cursor = 0;
        while (true) {
            int marker = format.indexOf("{}", cursor);
            if (marker < 0) {
                out.append(format, cursor, format.length());
                break;
            }
            out.append(format, cursor, marker);
            if (argIndex < args.length) {
                out.append(args[argIndex++]);
            } else {
                out.append("{}");
            }
            cursor = marker + 2;
        }
        return out.toString();
    }

    /** 无操作实现。 */
    final class Noop implements LogSink {
        private static final Noop INSTANCE = new Noop();

        private Noop() {
        }

        @Override
        public void info(String format, Object... args) {
        }

        @Override
        public void warn(String format, Object... args) {
        }

        @Override
        public void error(String format, Object... args) {
        }

        @Override
        public void debug(String format, Object... args) {
        }

        @Override
        public void error(String message, Throwable throwable) {
        }
    }

}
