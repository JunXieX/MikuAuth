package cn.miku.auth.auth;

import cn.miku.auth.config.MikuConfig;
import com.velocitypowered.api.event.command.CommandExecuteEvent;
import com.velocitypowered.api.event.player.PlayerChooseInitialServerEvent;
import com.velocitypowered.api.event.player.ServerConnectedEvent;
import com.velocitypowered.api.event.player.ServerPreConnectEvent;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.api.proxy.RegisteredServer;
import com.velocitypowered.api.proxy.ServerConnection;
import com.velocitypowered.api.proxy.server.ServerInfo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * 事件入口（AuthListener）直测：命令拦截、初始调度与转服门禁。
 *
 * <p>这些分支此前只有间接覆盖。其中两条对应真实的线上事故 / 安全门禁：
 * 初始调度必须使用事件自带的服务器名（用 {@code getCurrentServer()} 会让离线玩家
 * 永远无法注册），以及未认证玩家不得离开认证服（初始连接必须放行）。
 */
class AuthListenerTest {

    @TempDir
    Path tempDir;

    private ProxyServer server;
    private AuthManager authManager;
    private AuthListener listener;

    @BeforeEach
    void setUp() throws Exception {
        server = mock(ProxyServer.class);
        authManager = mock(AuthManager.class);
        // 用真实配置（默认值）：auth-server = "auth"、命令别名 = l/log、reg
        MikuConfig config = new MikuConfig();
        config.load(tempDir, null);
        listener = new AuthListener(server, LoggerFactory.getLogger("MikuAuthTest"), config, authManager);
    }

    @Test
    void unauthenticatedPlayerCannotRunNonAuthCommand() {
        CommandExecuteEvent event = mock(CommandExecuteEvent.class);
        Player player = mock(Player.class);
        when(event.getCommandSource()).thenReturn(player);
        when(event.getCommand()).thenReturn("/spawn");
        when(authManager.isAllowed(player)).thenReturn(false);

        listener.onCommand(event);

        verify(event).setResult(any(CommandExecuteEvent.CommandResult.class));
        verify(authManager).handleDeniedCommand(player);
    }

    @Test
    void unauthenticatedPlayerCanRunLoginCommand() {
        CommandExecuteEvent event = mock(CommandExecuteEvent.class);
        Player player = mock(Player.class);
        when(event.getCommandSource()).thenReturn(player);
        when(event.getCommand()).thenReturn("login");
        when(authManager.isAllowed(player)).thenReturn(false);

        listener.onCommand(event);

        verify(event, never()).setResult(any());
        verify(authManager, never()).handleDeniedCommand(any());
    }

    @Test
    void serverConnectedUsesServerFromEvent() {
        // 回归点：必须用 event.getServer() —— 在 ServerConnectedEvent 这一刻
        // player.getCurrentServer() 还没写回，用错会把"落在认证服"误判成"落在正式服"，
        // 离线玩家会被送服失败后直接踢下线，永远无法注册/登录
        ServerConnectedEvent event = mock(ServerConnectedEvent.class);
        Player player = mock(Player.class);
        RegisteredServer authServer = mock(RegisteredServer.class);
        ServerInfo info = mock(ServerInfo.class);
        when(event.getPlayer()).thenReturn(player);
        when(event.getServer()).thenReturn(authServer);
        when(authServer.getServerInfo()).thenReturn(info);
        when(info.getName()).thenReturn("auth");
        when(authManager.hasSession(player)).thenReturn(false);

        listener.onServerConnected(event);

        verify(authManager).handleConnected(player, "auth");
    }

    @Test
    void premiumPlayerIsSentDirectlyToTargetServer() {
        PlayerChooseInitialServerEvent event = mock(PlayerChooseInitialServerEvent.class);
        Player player = mock(Player.class);
        RegisteredServer target = mock(RegisteredServer.class);
        when(event.getPlayer()).thenReturn(player);
        when(player.getUsername()).thenReturn("Steve");
        when(authManager.lastLoginModeFor("Steve")).thenReturn(AuthManager.LoginMode.PREMIUM);
        when(authManager.resolvePostAuthTarget()).thenReturn(target);

        listener.onChooseInitialServer(event);

        verify(event).setInitialServer(target);
    }

    @Test
    void offlinePlayerWithoutSessionGoesToAuthServer() {
        PlayerChooseInitialServerEvent event = mock(PlayerChooseInitialServerEvent.class);
        Player player = mock(Player.class);
        RegisteredServer authServer = mock(RegisteredServer.class);
        when(event.getPlayer()).thenReturn(player);
        when(player.getUsername()).thenReturn("Alex");
        when(authManager.lastLoginModeFor("Alex")).thenReturn(AuthManager.LoginMode.OFFLINE);
        when(authManager.isSessionVerifiedFor("Alex")).thenReturn(false);
        when(server.getServer("auth")).thenReturn(Optional.of(authServer));

        listener.onChooseInitialServer(event);

        verify(event).setInitialServer(authServer);
    }

    @Test
    void unauthenticatedPlayerCannotLeaveAuthServerButInitialConnectionIsAllowed() {
        // 门禁 ①：初始连接（尚无当前服）必须放行，否则玩家进不来任何服务器
        ServerPreConnectEvent initial = mock(ServerPreConnectEvent.class);
        Player newcomer = mock(Player.class);
        when(initial.getPlayer()).thenReturn(newcomer);
        when(newcomer.getCurrentServer()).thenReturn(Optional.empty());
        when(authManager.isAllowed(newcomer)).thenReturn(false);

        listener.onServerPreConnect(initial);

        verify(initial, never()).setResult(any());

        // 门禁 ②：已落在认证服的未认证玩家改连正式服 → 拒绝
        ServerPreConnectEvent leave = mock(ServerPreConnectEvent.class);
        Player stranded = mock(Player.class);
        RegisteredServer lobby = mock(RegisteredServer.class);
        ServerInfo lobbyInfo = mock(ServerInfo.class);
        when(leave.getPlayer()).thenReturn(stranded);
        when(stranded.getCurrentServer()).thenReturn(Optional.of(mock(ServerConnection.class)));
        when(leave.getOriginalServer()).thenReturn(lobby);
        when(lobby.getServerInfo()).thenReturn(lobbyInfo);
        when(lobbyInfo.getName()).thenReturn("lobby");
        when(authManager.isAllowed(stranded)).thenReturn(false);

        listener.onServerPreConnect(leave);

        verify(leave).setResult(any(ServerPreConnectEvent.ServerResult.class));
    }
}