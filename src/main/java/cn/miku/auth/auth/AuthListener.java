package cn.miku.auth.auth;

import cn.miku.auth.config.MikuConfig;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.connection.DisconnectEvent;
import com.velocitypowered.api.event.connection.PostLoginEvent;
import com.velocitypowered.api.event.connection.PreLoginEvent;
import com.velocitypowered.api.event.player.GameProfileRequestEvent;
import com.velocitypowered.api.event.player.KickedFromServerEvent;
import com.velocitypowered.api.event.player.PlayerChooseInitialServerEvent;
import com.velocitypowered.api.event.player.ServerConnectedEvent;
import com.velocitypowered.api.event.player.ServerPreConnectEvent;
import com.velocitypowered.api.event.command.CommandExecuteEvent;
import com.velocitypowered.api.event.player.PlayerChatEvent;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.api.proxy.server.RegisteredServer;
import net.kyori.adventure.text.Component;

import java.net.InetSocketAddress;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;

/**
 * Velocity 事件入口：把代理事件接入认证状态机。
 *
 * <p>事件顺序参考：
 * PreLoginEvent → GameProfileRequestEvent → LoginEvent → PostLoginEvent
 * → PlayerChooseInitialServerEvent → ServerPreConnectEvent → ServerConnectedEvent。
 */
public final class AuthListener {

    /**
     * 与配置无关的固定白名单命令（小写、不含斜杠）。
     * mikuauth / mauth 供管理员在未认证状态下执行 reload 等操作，权限由命令自身校验；
     * mikuauth-close 由对话框"返回聊天栏"按钮触发。
     *
     * <p>login / register 及其别名不在此处硬编码：它们必须与 {@code config.yml} 的
     * aliases 保持一致，否则管理员改了别名后未认证玩家会被拦截（登录是唯一出路）。
     */
    private static final Set<String> STATIC_AUTH_COMMANDS =
            Set.of("mikuauth", "mauth", "mikuauth-close");
    /** 认证命令主名（别名由配置提供）。 */
    private static final Set<String> AUTH_COMMAND_ROOTS = Set.of("login", "register");

    private final ProxyServer server;
    private final Logger logger;
    private final MikuConfig config;
    private final AuthManager authManager;

    /** 正版 UUID 校验失败的待踢出玩家（PostLogin 时执行）。 */
    private final ConcurrentHashMap<UUID, Component> pendingDenials = new ConcurrentHashMap<>();

    public AuthListener(ProxyServer server, Logger logger, MikuConfig config, AuthManager authManager) {
        this.server = server;
        this.logger = logger;
        this.config = config;
        this.authManager = authManager;
    }

    // ---------------------------------------------------------------------
    // PreLogin：决定登录模式（正版强制校验 / 离线 / 基岩）
    // ---------------------------------------------------------------------

    /**
     * 异步决策：返回 EventTask 让 Velocity 挂起连接直到决策完成，Netty 线程零阻塞。
     *
     * <p>同时把来源 IP 交给决策链，用于在 PreLogin 阶段判定"同 IP 会话免密"
     * （判定结果会驱动初始调度：会话有效则直连目标服，跳过认证服）。
     */
    @Subscribe
    public com.velocitypowered.api.event.EventTask onPreLogin(PreLoginEvent event) {
        String username = event.getUsername();
        String ip = remoteIp(event);
        return com.velocitypowered.api.event.EventTask.resumeWhenComplete(
                authManager.decideLoginModeAsync(username, ip).thenAccept(decision -> {
                    switch (decision.mode()) {
                        case PREMIUM ->
                                event.setResult(PreLoginEvent.PreLoginComponentResult.forceOnlineMode());
                        case BEDROCK, OFFLINE ->
                                event.setResult(PreLoginEvent.PreLoginComponentResult.forceOfflineMode());
                        case DENIED ->
                                event.setResult(PreLoginEvent.PreLoginComponentResult.denied(decision.denyReason()));
                    }
                }));
    }

    /** 取连接来源 IP；不可用时返回 null（决策链会跳过会话判定）。 */
    private static String remoteIp(PreLoginEvent event) {
        try {
            InetSocketAddress address = event.getConnection().getRemoteAddress();
            return address == null || address.getAddress() == null
                    ? null : address.getAddress().getHostAddress();
        } catch (Throwable t) {
            return null;
        }
    }

    /** 取在线玩家来源 IP（断开事件用）。 */
    private static String remoteIp(Player player) {
        try {
            InetSocketAddress address = player.getRemoteAddress();
            return address == null || address.getAddress() == null
                    ? null : address.getAddress().getHostAddress();
        } catch (Throwable t) {
            return null;
        }
    }

    // ---------------------------------------------------------------------
    // GameProfileRequest：正版 UUID 校验（防昵称抢注）
    // ---------------------------------------------------------------------

    /**
     * Velocity 3.x 的 GameProfileRequestEvent 不支持拒绝连接，
     * 因此校验失败时记录待踢标记，玩家上线（PostLogin）后立即断开。
     */
    @Subscribe
    public void onGameProfileRequest(GameProfileRequestEvent event) {
        Component deny = authManager.verifyPremiumProfile(event.getUsername(), event.getGameProfile().getId());
        if (deny != null) {
            pendingDenials.put(event.getGameProfile().getId(), deny);
        }
    }

    /** 上线后立即踢出正版校验失败的连接。 */
    @Subscribe
    public void onPostLogin(PostLoginEvent event) {
        Component reason = pendingDenials.remove(event.getPlayer().getUniqueId());
        if (reason != null) {
            event.getPlayer().disconnect(reason);
        }
    }

    // ---------------------------------------------------------------------
    // 初始服务器选择：离线玩家进认证服，正版/基岩免密直连目标服
    // ---------------------------------------------------------------------

    /**
     * 初始调度（参考 LibreLogin/VeloAuth）：
     * <ul>
     *   <li><b>正版玩家</b>（决策 PREMIUM，代理已强制会话校验）→ 免密直连目标服；</li>
     *   <li><b>基岩玩家</b>（决策 BEDROCK，Floodgate 已验证）→ 免密直连目标服，
     *       同时规避 limbo 注册表数据与 Geyser 的兼容性问题
     *       （"Expected reader for registry"）；</li>
     *   <li><b>离线玩家且同 IP 会话有效</b>（PreLogin 已判定）→ 免密直连目标服，
     *       不必"先进认证服再被送走"；</li>
     *   <li><b>其余离线玩家</b> → 进入认证服完成注册/登录。</li>
     * </ul>
     */
    @Subscribe
    public void onChooseInitialServer(PlayerChooseInitialServerEvent event) {
        Player player = event.getPlayer();
        AuthManager.LoginMode mode = authManager.lastLoginModeFor(player.getUsername());
        boolean bypassLimbo = (mode == AuthManager.LoginMode.PREMIUM)
                || (mode == AuthManager.LoginMode.BEDROCK && config.bedrockAutoLogin())
                || authManager.isSessionVerifiedFor(player.getUsername());
        if (bypassLimbo) {
            RegisteredServer target = authManager.resolvePostAuthTarget();
            if (target != null) {
                event.setInitialServer(target);
                return;
            }
            logger.warn("[调度] {} 为免密玩家（{}）但未找到目标服，改为进入认证服", player.getUsername(), mode);
        }
        RegisteredServer auth = server.getServer(config.authServer()).orElse(null);
        if (auth != null) {
            event.setInitialServer(auth);
        }
    }

    // ---------------------------------------------------------------------
    // 认证服跳转控制
    // ---------------------------------------------------------------------

    /**
     * 未认证玩家禁止离开认证服。
     * 注意：初始连接（getCurrentServer 为空）必须放行，否则玩家无法进入任何服务器。
     */
    @Subscribe
    public void onServerPreConnect(ServerPreConnectEvent event) {
        Player player = event.getPlayer();
        if (authManager.isAllowed(player)) {
            return;
        }
        if (player.getCurrentServer().isEmpty()) {
            return; // 初始连接
        }
        String targetName = event.getOriginalServer().getServerInfo().getName();
        if (targetName.equalsIgnoreCase(config.authServer())) {
            return; // 回到认证服允许
        }
        event.setResult(ServerPreConnectEvent.ServerResult.denied());
    }

    /**
     * 玩家到达任意服务器时启动认证处理（每个连接生命周期仅一次）。
     *
     * <p>覆盖两类落点：认证服（离线玩家）与免密直连的目标服
     * （正版/基岩玩家）。已完成认证的玩家由 authenticated 标记短路。
     *
     * <p>这里把 {@code event.getServer()} 一并交给认证状态机：在 ServerConnectedEvent
     * 这一刻 {@code player.getCurrentServer()} 还没写回（实测），
     * 只靠它会把"落在认证服"误判成"落在正式服"，把离线玩家踢下线。
     */
    @Subscribe
    public void onServerConnected(ServerConnectedEvent event) {
        Player player = event.getPlayer();
        if (authManager.hasSession(player)) {
            return; // 已在认证流程中（重复触发）
        }
        authManager.handleConnected(player, event.getServer().getServerInfo().getName());
    }

    /** 未认证玩家被认证服踢出时直接断开，不重定向到正式服。 */
    @Subscribe
    public void onKickedFromServer(KickedFromServerEvent event) {
        if (!authManager.isAllowed(event.getPlayer())) {
            event.setResult(KickedFromServerEvent.DisconnectPlayer.create(event.getServerKickReason()
                    .orElse(Component.empty())));
        }
    }

    // ---------------------------------------------------------------------
    // 命令拦截：未认证玩家仅允许认证相关命令
    // ---------------------------------------------------------------------

    /**
     * 管理员交互式密码输入：把下一条聊天当作密码，并阻止其广播。
     *
     * <p>这里必须用 {@code ChatResult.message("")} 清空内容，<b>不能</b>用
     * {@code denied()}——后者会把玩家直接踢下线（实测踩坑）。
     * 返回 true 表示这条消息已被消费为密码输入，绝不广播。
     */
    @Subscribe
    public void onChat(PlayerChatEvent event) {
        if (authManager.consumePasswordInput(event.getPlayer(), event.getMessage())) {
            event.setResult(PlayerChatEvent.ChatResult.message(""));
        }
    }

    @Subscribe
    public void onCommand(CommandExecuteEvent event) {
        if (!(event.getCommandSource() instanceof Player player)) {
            return;
        }
        if (authManager.isAllowed(player)) {
            return;
        }
        String label = event.getCommand().trim();
        int space = label.indexOf(' ');
        if (space > 0) {
            label = label.substring(0, space);
        }
        label = label.replaceFirst("^/", "").toLowerCase(Locale.ROOT);
        if (isAuthCommand(label)) {
            return;
        }
        event.setResult(CommandExecuteEvent.CommandResult.denied());
        authManager.handleDeniedCommand(player);
    }

    /**
     * 是否为未认证玩家可用的命令。
     * 别名从配置实时读取，保证与命令注册所用的 aliases 完全一致（含 /mikuauth reload 之后）。
     */
    private boolean isAuthCommand(String label) {
        if (STATIC_AUTH_COMMANDS.contains(label) || AUTH_COMMAND_ROOTS.contains(label)) {
            return true;
        }
        return config.loginAliases().contains(label) || config.registerAliases().contains(label);
    }

    // ---------------------------------------------------------------------
    // 断线清理
    // ---------------------------------------------------------------------

    @Subscribe
    public void onDisconnect(DisconnectEvent event) {
        Player player = event.getPlayer();
        // 登录阶段断开原因分析（正版会话校验失败 / 同名冲突等）
        if (event.getLoginStatus() != DisconnectEvent.LoginStatus.SUCCESSFUL_LOGIN) {
            authManager.logJoinFailure(player.getUsername(), event.getLoginStatus(),
                    remoteIp(player));
        }
        pendingDenials.remove(player.getUniqueId());
        authManager.handleDisconnect(player.getUsername(), player.getUniqueId());
    }
}
