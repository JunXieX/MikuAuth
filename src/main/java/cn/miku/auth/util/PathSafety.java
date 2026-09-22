package cn.miku.auth.util;

import org.slf4j.Logger;

import java.nio.file.Path;

/**
 * 配置里"文件名"类设置的落地校验。
 *
 * <p><b>为什么需要</b>：这些值最终会被 {@link Path#resolve} 拼到插件数据目录上，
 * 而 {@code resolve} 遇到绝对路径会<b>直接采用</b>、遇到 {@code ../} 会越出目录 ——
 * 等于把"改一个配置字符串"变成"在任意路径写文件"（例如把
 * {@code audit.backend-kick-file} 指到 {@code ../../server.properties}，
 * 记录内容会被追加进服务端配置）。这里统一规范化并做越界检查，
 * 越界一律拒绝并退回默认文件名。
 */
public final class PathSafety {

    private PathSafety() {
    }

    /**
     * 把配置里的文件名安全地解析到基准目录之内。
     *
     * @param base       基准目录（插件数据目录）
     * @param configured 配置值；为空时用 {@code fallback}
     * @param fallback   默认文件名
     * @param logger     可为 null
     * @return 保证落在 {@code base} 之内的路径
     */
    public static Path resolveInside(Path base, String configured, String fallback, Logger logger) {
        Path normalizedBase = base.toAbsolutePath().normalize();
        String name = configured == null || configured.isBlank() ? fallback : configured.trim();
        Path resolved = normalizedBase.resolve(name).normalize();
        if (resolved.equals(normalizedBase) || !resolved.startsWith(normalizedBase)) {
            if (logger != null) {
                logger.warn("[安全] 配置的文件名 '{}' 指向数据目录之外，已改用默认值 '{}'", name, fallback);
            }
            return normalizedBase.resolve(fallback);
        }
        return resolved;
    }
}
