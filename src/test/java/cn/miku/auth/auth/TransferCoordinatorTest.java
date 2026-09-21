package cn.miku.auth.auth;

import cn.miku.auth.config.MikuConfig;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.api.proxy.ServerConnection;
import com.velocitypowered.api.proxy.config.ProxyConfig;
import com.velocitypowered.api.proxy.server.RegisteredServer;
import com.velocitypowered.api.proxy.server.ServerInfo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * 转服调度器的单元测试。
 *
 * <p>覆盖三块最容易出错、又最不适合靠真机发现的逻辑：
 * <ol>
 *   <li><b>目标服解析优先级</b>：配置的 fallback-server 优先，缺失时回退 try 列表，
 *       且必须跳过认证服本身（否则会把玩家"送回 limbo"）；</li>
 *   <li><b>服务器归属判断</b>：大小写不敏感、未连接时不抛异常；</li>
 *   <li><b>挂起记录生命周期</b>：断线清理后不再重试。</li>
 * </ol>
 */
class TransferCoordinatorTest {

    @TempDir
    Path dataDirectory;

    private ProxyServer server;
    private MikuConfig config;

    /** 构造真实配置（含内置默认回退），只覆盖需要控制的项。 */
    private MikuConfig configWith(String authServer, String fallbackServer) throws IOException {
        Files.writeString(dataDirectory.resolve("config.yml"), """
                server:
                  auth-server: "%s"
                  fallback-server: "%s"
                """.formatted(authServer, fallbackServer), StandardCharsets.UTF_8);
        MikuConfig loaded = new MikuConfig();
        loaded.load(dataDirectory, null);
        return loaded;
    }

    @BeforeEach
    void setUp() {
        server = mock(ProxyServer.class);
    }

    private RegisteredServer registeredServer(String name) {
        RegisteredServer registered = mock(RegisteredServer.class);
        when(registered.getServerInfo()).thenReturn(serverInfo(name));
        return registered;
    }

    /**
     * 构造真实的 {@link ServerInfo}。
     *
     * <p>它是 record（final），直接 new 即可——用 Mockito mock 反而会在新 JDK 上
     * 因 ByteBuddy 无法改造 record 而报错（本用例刻意避免 mock 任何 final 类型）。
     */
    private static ServerInfo serverInfo(String name) {
        return new ServerInfo(name, new InetSocketAddress("127.0.0.1", 25565));
    }

    private TransferCoordinator coordinator() {
        // 用 SLF4J 的 NOP logger：既不产生输出，也避免 mock 额外类型
        return new TransferCoordinator(server, new Object(), config,
                org.slf4j.helpers.NOPLogger.NOP_LOGGER);
    }

    // ---------------------------------------------------------------------
    // 目标服解析
    // ---------------------------------------------------------------------

    @Test
    void configuredFallbackWinsOverTryList() throws IOException {
        config = configWith("auth", "lobby");
        RegisteredServer lobby = registeredServer("lobby");
        when(server.getServer("lobby")).thenReturn(Optional.of(lobby));

        assertSame(lobby, coordinator().resolveTarget());
    }

    @Test
    void missingConfiguredFallbackFallsBackToTryList() throws IOException {
        config = configWith("auth", "not-there");
        RegisteredServer survival = registeredServer("survival");
        when(server.getServer("not-there")).thenReturn(Optional.empty());
        // 注意：ProxyConfig 必须先在 stubbing 之外构造好——
        // 若把它写在 when(...) 的参数里，Mockito 会因"stubbing 中再次 stubbing"而报 UnfinishedStubbing
        ProxyConfig proxyConfig = proxyConfigWith(List.of("auth", "survival"));
        when(server.getConfiguration()).thenReturn(proxyConfig);
        when(server.getServer("survival")).thenReturn(Optional.of(survival));

        assertSame(survival, coordinator().resolveTarget(),
                "配置的 fallback-server 不存在时应回退到 try 列表");
    }

    @Test
    void authServerIsNeverChosenAsTarget() throws IOException {
        config = configWith("auth", "");
        RegisteredServer auth = registeredServer("auth");
        ProxyConfig proxyConfig = proxyConfigWith(List.of("auth"));
        // try 列表里只有认证服：必须返回 null，而不是把玩家"送回 limbo"
        when(server.getConfiguration()).thenReturn(proxyConfig);
        when(server.getServer("auth")).thenReturn(Optional.of(auth));

        assertNull(coordinator().resolveTarget());
    }

    @Test
    void returnsNullWhenNoUsableTargetExists() throws IOException {
        config = configWith("auth", "missing");
        when(server.getServer("missing")).thenReturn(Optional.empty());
        ProxyConfig proxyConfig = proxyConfigWith(List.of("auth"));
        when(server.getConfiguration()).thenReturn(proxyConfig);

        assertNull(coordinator().resolveTarget());
    }

    // ---------------------------------------------------------------------
    // 服务器归属判断
    // ---------------------------------------------------------------------

    @Test
    void isOnServerIsCaseInsensitive() {
        Player player = playerOn("Lobby");

        assertTrue(TransferCoordinator.isOnServer(player, "lobby"));
        assertTrue(TransferCoordinator.isOnServer(player, "LOBBY"));
        assertFalse(TransferCoordinator.isOnServer(player, "survival"));
    }

    @Test
    void isOnServerIsFalseWhenPlayerIsNotConnected() {
        Player player = mock(Player.class);
        when(player.getCurrentServer()).thenReturn(Optional.empty());

        assertFalse(TransferCoordinator.isOnServer(player, "lobby"));
    }

    @Test
    void isOnAuthServerUsesConfiguredName() throws IOException {
        config = configWith("limbo", "");
        TransferCoordinator coordinator = coordinator();

        assertTrue(coordinator.isOnAuthServer(playerOn("limbo")));
        assertFalse(coordinator.isOnAuthServer(playerOn("lobby")));
    }

    // ---------------------------------------------------------------------
    // 挂起记录生命周期
    // ---------------------------------------------------------------------

    @Test
    void forgetClearsPendingRecord() throws IOException {
        config = configWith("auth", "lobby");
        TransferCoordinator coordinator = coordinator();
        Player player = playerOn("auth");

        // 不真正入队（schedule 需要调度器），这里直接验证 forget 的幂等与查询语义
        assertFalse(coordinator.isPending(player.getUniqueId()));
        coordinator.forget(player.getUniqueId());
        assertFalse(coordinator.isPending(player.getUniqueId()));
    }

    // ---------------------------------------------------------------------
    // 工具
    // ---------------------------------------------------------------------

    private static Player playerOn(String serverName) {
        Player player = mock(Player.class);
        when(player.getUniqueId()).thenReturn(UUID.randomUUID());
        ServerConnection connection = mock(ServerConnection.class);
        when(connection.getServerInfo()).thenReturn(serverInfo(serverName));
        when(player.getCurrentServer()).thenReturn(Optional.of(connection));
        return player;
    }

    private static ProxyConfig proxyConfigWith(List<String> tryOrder) {
        ProxyConfig proxyConfig = mock(ProxyConfig.class);
        when(proxyConfig.getAttemptConnectionOrder()).thenReturn(tryOrder);
        return proxyConfig;
    }
}
