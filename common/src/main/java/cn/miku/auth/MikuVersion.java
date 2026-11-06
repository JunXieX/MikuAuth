package cn.miku.auth;

/**
 * 插件版本（唯一的代码内来源）。
 *
 * <p>必须与 {@code gradle.properties} 的 {@code version} 一致；构建时由
 * {@code :velocity:checkVersionConstant} 任务校验，改漏直接失败。
 *
 * <p>放在公共层而不是主类里：主类属于 {@code :velocity}，而 {@code :common} 里的
 * HTTP User-Agent 与驱动下载器也需要版本号，不能反向依赖平台模块。
 */
public final class MikuVersion {

    public static final String VERSION = "3.9.1";

    private MikuVersion() {
    }
}
