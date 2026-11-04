package cn.miku.auth.auth;

import cn.miku.auth.config.MikuConfig;
import cn.miku.auth.dialog.DialogService;
import com.velocitypowered.api.event.EventTask;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.player.configuration.PlayerConfigurationEvent;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;

import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Set;
import org.slf4j.Logger;

/**
 * 配置阶段认证闸门（{@code login.mode: pre}）。
 *
 * <p><b>原理</b>：Velocity 的 {@link PlayerConfigurationEvent} 是"等待型"事件 ——
 * 代理会等它返回的 future 完成后，才写 {@code finish_configuration} 并把连接切到 PLAY
 * （见 {@code ClientConfigSessionHandler#handleBackendFinishUpdate}）。因此只要在这里返回一个
 * "认证完成才 complete" 的 future，玩家就会停在 configuration 阶段：注册表数据已下发、
 * 世界还没开始加载，正是"进服前登录"最自然的时机。
 *
 * <p><b>不需要动协议</b>：不 cancel 任何包、不补发 {@code finish_configuration}、
 * 不碰 encoder 状态 —— 与"扣包再放行"相比，这条路径不会有状态机撕裂的风险。
 *
 * <p><b>为什么仍要 limbo</b>：代理不能把客户端停在自己身上（
 * {@code AuthSessionHandler#connectToInitialServer} 在拿不到初始服时直接断开），
 * 所以玩家必然先落在一台真实后端上。这里让他落在认证服 —— 于是未认证连接（含假连接压测）
 * 只打 limbo，目标服零增量。
 *
 * <p><b>降级</b>：客户端版本不支持配置阶段对话框、或 packetevents 缺类、或发包失败时，
 * 闸门立刻放行，玩家按现有 {@code post} 流程在 limbo 里正常登录 —— 功能不缺失，只是晚一步。
 */
public final class PreAuthGate {

    /** 无需等待的完成态（配置阶段不该被扣住的所有情形都返回它）。 */
    private static final CompletableFuture<Void> DONE = CompletableFuture.completedFuture(null);

    /** 一个被扣住的连接。 */
    private static final class Held {
        /** 放行信号：完成即代表认证结束（成功、超时踢出、断线清理都算）。 */
        final CompletableFuture<Void> finish = new CompletableFuture<>();
        final long startedAt = System.currentTimeMillis();
    }

    private final ProxyServer server;
    private final MikuConfig config;
    private final Logger logger;
    private final DialogService dialogService;

    /** 认证状态机（由插件在构造后注入，避免与 AuthManager 形成构造期循环依赖）。 */
    private volatile AuthManager authManager;

    /** 当前被扣在配置阶段的连接。 */
    private final ConcurrentHashMap<UUID, Held> held = new ConcurrentHashMap<>();
    /**
     * 刚由闸门放行的连接。
     *
     * <p>用途：放行后玩家才真正进入 limbo 的 play 阶段，此时 {@code ServerConnectedEvent}
     * 会到达；状态机据此补发成功提示并安排转服（这条连接没有走过 {@code handleConnected}
     * 的常规认证路径，不能靠它的分支推断）。
     */
    private final Set<UUID> justReleased = ConcurrentHashMap.newKeySet();

    public PreAuthGate(ProxyServer server, MikuConfig config, Logger logger, DialogService dialogService) {
        this.server = server;
        this.config = config;
        this.logger = logger;
        this.dialogService = dialogService;
    }

    /** 注入认证状态机（插件装配时调用一次）。 */
    public void bind(AuthManager authManager) {
        this.authManager = authManager;
    }

    // ---------------------------------------------------------------------
    // 闸门
    // ---------------------------------------------------------------------

    /**
     * 配置阶段结束前的拦截点。
     *
     * <p><b>返回类型必须是 {@code EventTask}</b>：Velocity 的事件派发只接受
     * {@code void} 或 {@code EventTask}（见 {@code VelocityEventManager} 的返回类型校验），
     * 而对 {@code @AwaitingEvent} 事件，返回的 task 会被等待 —— 这就是"扣住配置阶段"的开关。
     * 需要放行时返回一个已完成的 task，语义等同"不等待"。
     */
    @Subscribe
    public EventTask onPlayerConfiguration(PlayerConfigurationEvent event) {
        Player player = event.player();
        String serverName = event.server() == null
                ? null : event.server().getServerInfo().getName();
        AuthManager manager = authManager;
        boolean needsAuth = manager != null && manager.needsConfigPhaseAuth(player);
        boolean clientSupported = dialogService.supportsConfigPhase(player);
        if (!shouldHold(config.loginMode(), DialogService.configPhaseSupportedByRuntime(),
                serverName, config.authServer(), needsAuth, clientSupported)) {
            return EventTask.resumeWhenComplete(DONE);
        }
        Held entry = new Held();
        // 同一条连接重复触发（例如代理侧重试）时，旧闸门必须先放行，否则它永远等不到结果
        Held previous = held.put(player.getUniqueId(), entry);
        if (previous != null) {
            previous.finish.complete(null);
        }
        logger.debug("[认证] {} 进入配置阶段，已扣留至认证完成（server={}）", player.getUsername(), serverName);
        manager.beginConfigAuth(player);
        return EventTask.resumeWhenComplete(entry.finish);
    }

    /**
     * 是否应当扣留这条连接（纯函数，便于单测）。
     *
     * @param mode           登录模式（post / pre）
     * @param runtimeSupport 运行期 packetevents 是否具备配置阶段对话框类
     * @param serverName     本次配置阶段所属服务器名（可能为 null）
     * @param authServer     配置的认证服名
     * @param needsAuth      该连接是否仍需要密码认证
     * @param clientSupport  该客户端能否接收配置阶段对话框
     */
    static boolean shouldHold(String mode, boolean runtimeSupport, String serverName,
                              String authServer, boolean needsAuth, boolean clientSupport) {
        if (!MikuConfig.LOGIN_MODE_PRE.equals(mode)) {
            return false;
        }
        if (!runtimeSupport || !clientSupport || !needsAuth) {
            return false;
        }
        // 只拦认证服的配置阶段：玩家认证完成后再切目标服时会再走一次 configuration，
        // 那时若还扣住就会把已登录玩家重新拉回登录框
        return serverName != null && authServer != null && serverName.equalsIgnoreCase(authServer);
    }

    /** 放行：认证成功（或决定降级为 post 流程）。 */
    public void release(Player player) {
        Held entry = held.remove(player.getUniqueId());
        if (entry == null) {
            return;
        }
        justReleased.add(player.getUniqueId());
        entry.finish.complete(null);
        logger.debug("[认证] {} 已放行进入世界（配置阶段认证结束）", player.getUsername());
    }

    /** 丢弃闸门状态（断线、踢出、插件关停）。 */
    public void forget(UUID playerId) {
        Held entry = held.remove(playerId);
        if (entry != null) {
            entry.finish.complete(null);
        }
    }

    /** 该连接当前是否被扣在配置阶段。 */
    public boolean isHeld(UUID playerId) {
        return held.containsKey(playerId);
    }

    /** 已扣留时长（秒）；未被扣留返回 0。诊断用。 */
    public long heldSeconds(UUID playerId) {
        Held entry = held.get(playerId);
        return entry == null ? 0L : (System.currentTimeMillis() - entry.startedAt) / 1000L;
    }

    /** 当前被扣住的连接数（诊断/日志用）。 */
    public int heldCount() {
        return held.size();
    }

    /**
     * 消费"刚放行"标记。
     *
     * @return true = 这条连接是配置阶段认证成功后放行的，调用方应补发成功提示并安排转服
     */
    public boolean consumeJustReleased(UUID playerId) {
        return justReleased.remove(playerId);
    }

    /**
     * 心跳：超时未完成认证的连接直接断开。
     *
     * <p>配置阶段没有聊天栏，玩家界面上只有"加载地形"与对话框，超时必须由服务端兜底，
     * 否则连接会一直占着 limbo 的配置槽位。
     */
    public void tick() {
        if (held.isEmpty()) {
            return;
        }
        int timeout = config.preAuthTimeoutSeconds();
        long now = System.currentTimeMillis();
        for (var entry : held.entrySet()) {
            Held heldEntry = entry.getValue();
            if (now - heldEntry.startedAt < timeout * 1000L) {
                continue;
            }
            Player player = server.getPlayer(entry.getKey()).orElse(null);
            AuthManager manager = authManager;
            if (player == null || manager == null) {
                forget(entry.getKey());
                continue;
            }
            logger.info("[认证] {} 配置阶段等待认证超时（{} 秒），已断开", player.getUsername(), timeout);
            // kick 内部会走 cleanup → forget，从而完成 future；下面这行是兜底
            manager.kick(player, "kick.auth-timeout");
            forget(entry.getKey());
        }
    }

    /** 插件关停：放行所有等待中的连接（它们本来就会被代理断开，绝不能让 future 悬挂）。 */
    public void shutdown() {
        for (Held entry : held.values()) {
            entry.finish.complete(null);
        }
        held.clear();
        justReleased.clear();
    }
}
