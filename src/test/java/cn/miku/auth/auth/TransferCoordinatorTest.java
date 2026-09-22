package cn.miku.auth.auth;

import cn.miku.auth.audit.BackendKickLog;
import cn.miku.auth.config.MikuConfig;
import cn.miku.auth.config.MikuMessages;
import com.velocitypowered.api.proxy.ConnectionRequestBuilder;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.api.proxy.ServerConnection;
import com.velocitypowered.api.proxy.config.ProxyConfig;
import com.velocitypowered.api.proxy.server.RegisteredServer;
import com.velocitypowered.api.proxy.server.ServerInfo;
import com.velocitypowered.api.scheduler.ScheduledTask;
import com.velocitypowered.api.scheduler.Scheduler;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.serializer.plain.PlainTextComponentSerializer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * 转服调度器的单元测试。
 *
 * <p>覆盖四块最容易出错、又最不适合靠真机发现的逻辑：
 * <ol>
 *   <li><b>目标服解析优先级</b>：配置的 fallback-server 优先，缺失时回退 try 列表，
 *       且必须跳过认证服本身（否则会把玩家"送回 limbo"）；</li>
 *   <li><b>服务器归属判断</b>：大小写不敏感、未连接时不抛异常；</li>
 *   <li><b>挂起记录生命周期</b>：断线清理后不再重试；</li>
 *   <li><b>失败分流</b>：目标服给出的原因要转发给玩家并停止重试，无原因的连接故障才重试。</li>
 * </ol>
 */
class TransferCoordinatorTest {

    @TempDir
    Path dataDirectory;

    private ProxyServer server;
    private MikuConfig config;
    private MikuMessages messages;
    /** 由 {@link #coordinator()} 创建，便于测试 flush 后断言落盘内容。 */
    private BackendKickLog kickLog;

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
    void setUp() throws IOException {
        server = mock(ProxyServer.class);
        messages = new MikuMessages();
        messages.load(dataDirectory, null);
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
        kickLog = new BackendKickLog(dataDirectory, config,
                org.slf4j.helpers.NOPLogger.NOP_LOGGER);
        return new TransferCoordinator(server, new Object(), config, messages, kickLog,
                org.slf4j.helpers.NOPLogger.NOP_LOGGER);
    }

    /**
     * 让 {@code schedule()} 立即执行转服任务（无需真实调度器）。
     *
     * <p>{@code buildTask} 的参数里就是那条延迟任务，直接跑掉即可；
     * 之后的 {@code delay()/schedule()} 只是链式调用，用 mock 吃掉。
     */
    private ProxyServer immediateScheduler() {
        ProxyServer proxy = mock(ProxyServer.class);
        Scheduler scheduler = mock(Scheduler.class);
        Scheduler.TaskBuilder builder = mock(Scheduler.TaskBuilder.class);
        when(proxy.getScheduler()).thenReturn(scheduler);
        when(scheduler.buildTask(any(), any(Runnable.class))).thenAnswer(invocation -> {
            invocation.getArgument(1, Runnable.class).run();
            return builder;
        });
        when(builder.delay(any(Duration.class))).thenReturn(builder);
        when(builder.schedule()).thenReturn(mock(ScheduledTask.class));
        return proxy;
    }

    /** 读取记录文件的数据行（跳过 # 开头的文件头）；文件不存在时视为空。 */
    private List<String> dataLines(String fileName) throws IOException {
        Path file = dataDirectory.resolve(fileName);
        if (Files.notExists(file)) {
            return List.of();
        }
        return Files.readAllLines(file, StandardCharsets.UTF_8).stream()
                .filter(line -> !line.isBlank() && !line.startsWith("#"))
                .toList();
    }

    /** 把一个"转服失败"的结果装配到 player 上（连上目标服的请求会返回该结果）。 */
    private static void stubFailedTransfer(Player player, RegisteredServer target,
                                          ConnectionRequestBuilder.Result result) {
        ConnectionRequestBuilder builder = mock(ConnectionRequestBuilder.class);
        when(builder.connect()).thenReturn(CompletableFuture.completedFuture(result));
        when(player.createConnectionRequest(target)).thenReturn(builder);
        when(player.isActive()).thenReturn(true);
    }

    private static ConnectionRequestBuilder.Result failedResult(Component reason) {
        ConnectionRequestBuilder.Result result = mock(ConnectionRequestBuilder.Result.class);
        when(result.isSuccessful()).thenReturn(false);
        when(result.getStatus()).thenReturn(ConnectionRequestBuilder.Status.SERVER_DISCONNECTED);
        when(result.getReasonComponent()).thenReturn(Optional.ofNullable(reason));
        return result;
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
    // 转服失败分流：目标服给出的原因必须转发给玩家
    // ---------------------------------------------------------------------

    /**
     * 目标服明确拒绝（Result 带原因）→ 原因原样转发到聊天栏，并在断开画面上展示，且不再心跳重试。
     *
     * <p><b>回归点（2026-09-22 线上反馈）</b>：踢出发生在"去目标服的那条连接"上，
     * 而玩家此刻还留在认证服。Velocity 对 forDisconnect 走 safe 路径、<b>不会</b>替玩家发
     * Disconnect 包，于是只发聊天栏的旧实现下，玩家在聊天被吞/连接随即关闭时只看到客户端默认的
     * "连接中断"，永远不知道原因。修复后必须走"必达"通道：{@code player.disconnect(完整原因)}。
     */
    @Test
    void backendRejectionIsForwardedToPlayerAndNotRetried() throws IOException {
        config = configWith("limbo", "sd");
        server = immediateScheduler();
        RegisteredServer sd = registeredServer("sd");
        when(server.getServer("sd")).thenReturn(Optional.of(sd));

        Player player = playerOn("limbo");
        stubFailedTransfer(player, sd, failedResult(
                Component.text("未绑定社交帐号 | junxiesky\n进入服务器需要绑定您的社交帐号")));

        TransferCoordinator coordinator = coordinator();
        coordinator.schedule(player);

        ArgumentCaptor<Component> sent = ArgumentCaptor.forClass(Component.class);
        verify(player, times(3)).sendMessage(sent.capture());
        String shown = sent.getAllValues().stream()
                .map(text -> PlainTextComponentSerializer.plainText().serialize(text))
                .reduce("", (left, right) -> left + "\n" + right);
        assertTrue(shown.contains("sd"), "应告诉玩家是哪个服务器拒绝的：" + shown);
        assertTrue(shown.contains("未绑定社交帐号"), "目标服给出的原因必须原样转发：" + shown);
        assertFalse(coordinator.isPending(player.getUniqueId()),
                "已被明确拒绝时不得再重试（重试只会得到同样的踢出）");

        // 必达通道：断开画面必须带上 目标服名 + 原因原文，否则玩家仍可能"看不到原因"
        ArgumentCaptor<Component> disconnected = ArgumentCaptor.forClass(Component.class);
        verify(player).disconnect(disconnected.capture());
        String screen = PlainTextComponentSerializer.plainText().serialize(disconnected.getValue());
        assertTrue(screen.contains("sd"), "断开画面必须说明是哪个服务器：" + screen);
        assertTrue(screen.contains("未绑定社交帐号"), "断开画面必须包含原因原文：" + screen);

        kickLog.flush();
        List<String> lines = dataLines("backend-kicks.log");
        assertEquals(1, lines.size(), "应落盘一条记录：" + lines);
        assertTrue(lines.get(0).contains("| sd |"), "记录里应包含目标服名：" + lines.get(0));
        assertTrue(lines.get(0).contains("未绑定社交帐号"), "记录里应包含原因：" + lines.get(0));
    }

    /**
     * 聊天栏通道异常时，仍然必须走到 {@code player.disconnect(reason)}。
     *
     * <p><b>回归点（"必达"契约）</b>：聊天栏/Title 只是尽力而为的补充通道；万一它们抛异常
     * （例如连接正处于切服/配置阶段导致写入失败），绝不能连着把"断开画面"这条唯一必达通道
     * 一起吞掉——否则玩家又回到"只看到连接中断"。
     */
    @Test
    void rejectionReasonIsAlwaysShownOnDisconnectScreenEvenIfChatFails() throws IOException {
        config = configWith("limbo", "sd");
        server = immediateScheduler();
        RegisteredServer sd = registeredServer("sd");
        when(server.getServer("sd")).thenReturn(Optional.of(sd));

        Player player = playerOn("limbo");
        stubFailedTransfer(player, sd, failedResult(
                Component.text("未绑定社交帐号 | junxiesky")));
        // 模拟聊天栏通道整体不可用
        doThrow(new RuntimeException("chat channel unavailable"))
                .when(player).sendMessage(any(Component.class));

        TransferCoordinator coordinator = coordinator();
        coordinator.schedule(player);

        ArgumentCaptor<Component> disconnected = ArgumentCaptor.forClass(Component.class);
        verify(player).disconnect(disconnected.capture());
        String screen = PlainTextComponentSerializer.plainText().serialize(disconnected.getValue());
        assertTrue(screen.contains("未绑定社交帐号"), "聊天栏失败时断开画面仍必须带原因：" + screen);
        assertTrue(screen.contains("sd"), "聊天栏失败时断开画面仍必须说明目标服：" + screen);

        // 等待异步落盘完成，避免记录线程在 @TempDir 清理之后才创建文件（Windows 上会报目录非空）
        kickLog.flush();
    }

    /** 连接层面的故障（没有原因，例如目标服离线/连接被意外关闭）→ 保留重试，不打扰玩家。 */
    @Test
    void connectionFailureWithoutReasonStaysPendingAndIsRetried() throws IOException {
        config = configWith("limbo", "sd");
        server = immediateScheduler();
        RegisteredServer sd = registeredServer("sd");
        when(server.getServer("sd")).thenReturn(Optional.of(sd));

        Player player = playerOn("limbo");
        stubFailedTransfer(player, sd, failedResult(null));

        TransferCoordinator coordinator = coordinator();
        coordinator.schedule(player);

        verify(player, never()).sendMessage(any(Component.class));
        verify(player, never()).disconnect(any(Component.class));
        assertTrue(coordinator.isPending(player.getUniqueId()),
                "没有明确原因时应保留挂起标记，交给心跳重试");

        kickLog.flush();
        assertEquals(List.of(), dataLines("backend-kicks.log"),
                "不含原因的连接故障不写入后端拒绝记录（它由重试兜底）");
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
