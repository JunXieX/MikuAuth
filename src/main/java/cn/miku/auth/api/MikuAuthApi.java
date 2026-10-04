package cn.miku.auth.api;

import com.velocitypowered.api.proxy.Player;

import java.util.UUID;

/**
 * MikuAuth 对外查询接口：供其它 Velocity 插件判断某个玩家是否已完成认证。
 *
 * <p><b>怎么拿到实现</b>：用 {@link MikuAuthProvider#get()}，不要依赖 MikuAuth 的主类：
 * <pre>{@code
 * MikuAuthProvider.get().ifPresent(api -> {
 *     if (api.isAuthenticated(player.getUniqueId())) {
 *         // 已认证：放行该玩家的业务逻辑
 *     }
 * });
 * }</pre>
 * MikuAuth 未安装、未启用或已停用时返回空，调用方按"未认证"处理即可。
 *
 * <p><b>语义</b>：查询的是<b>当前这条连接</b>的认证状态。正版免密、基岩版免密、
 * 同 IP 会话免密与密码登录都会让它为 {@code true}；玩家一断线立即变回 {@code false}
 * （认证状态不跨连接保存）。因此它适合"玩家执行操作前检查是否已登录"这类场景，
 * 不适合当作持久化的账号归属判断。
 *
 * <p>线程安全：可从任意线程调用，不会阻塞（只读内存状态）。
 */
public interface MikuAuthApi {

    /**
     * 该玩家当前是否已通过认证。
     *
     * @param playerId 玩家 UUID；{@code null} 一律返回 {@code false}
     * @return true = 已认证（含正版 / 基岩版 / 会话免密）；
     *         false = 未认证、已断线，或该玩家从未完成过认证
     */
    boolean isAuthenticated(UUID playerId);

    /** 便捷重载：直接传在线玩家对象。 */
    default boolean isAuthenticated(Player player) {
        return player != null && isAuthenticated(player.getUniqueId());
    }
}