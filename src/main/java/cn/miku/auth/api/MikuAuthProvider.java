package cn.miku.auth.api;

import java.util.Optional;

/**
 * MikuAuth API 的入口。
 *
 * <p>插件初始化完成时由 MikuAuth 本体注册实现，代理关停时撤销；因此 {@link #get()}
 * 在"MikuAuth 未安装 / 加载失败 / 已停用"这三种情况下都返回空——调用方只需处理空，
 * 不必再区分具体原因。
 *
 * <p><b>为什么用静态入口，而不是从 {@code PluginManager} 取插件实例再做类型转换</b>：
 * 调用方通常只想问一个问题（"这人登录了吗"），不该为了拿到实例去走一遍插件容器、
 * 再对 {@code Optional<Object>} 做 {@code instanceof} 判断，甚至把 MikuAuth 的主类
 * 写进自己的依赖。静态入口让调用点只有一行。
 *
 * <p>之所以能这样用：Velocity 的插件类加载器在自身与父加载器都找不到类时，会回退到
 * 其它插件的类加载器并**复用同一个 Class 对象**，因此这里的状态对所有插件是同一份
 * （不会出现"A 插件注册、B 插件读到 null"）。
 */
public final class MikuAuthProvider {

    /** volatile：注册发生在插件初始化、读取可能来自任意插件线程。 */
    private static volatile MikuAuthApi api;

    private MikuAuthProvider() {
    }

    /** 取 API 实现；MikuAuth 未安装、未启用或已停用时为空。 */
    public static Optional<MikuAuthApi> get() {
        return Optional.ofNullable(api);
    }

    /**
     * 注册 / 撤销实现。
     *
     * <p>仅供 MikuAuth 本体在初始化收尾与关停时调用；第三方插件不需要、也不应该调用它。
     *
     * @param instance 实现；{@code null} 表示撤销（关停时）
     */
    public static void register(MikuAuthApi instance) {
        api = instance;
    }
}