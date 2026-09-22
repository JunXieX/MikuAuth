package cn.miku.auth.auth;

import cn.miku.auth.config.MikuConfig;
import cn.miku.auth.audit.AuditEntry;
import cn.miku.auth.audit.AuditLogger;
import cn.miku.auth.audit.BackendKickLog;
import cn.miku.auth.audit.PremiumConflictLog;
import cn.miku.auth.audit.AuditRepository;
import cn.miku.auth.config.MikuMessages;
import cn.miku.auth.database.AuthRepository;
import cn.miku.auth.database.DatabaseManager;
import cn.miku.auth.database.StoredPlayer;
import cn.miku.auth.dialog.DialogService;
import cn.miku.auth.display.DisplayManager;
import cn.miku.auth.premium.PremiumService;
import cn.miku.auth.security.PasswordHasher;
import com.velocitypowered.api.event.connection.DisconnectEvent;
import com.velocitypowered.api.proxy.ConnectionRequestBuilder;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.api.proxy.server.RegisteredServer;
import com.velocitypowered.api.scheduler.ScheduledTask;
import com.velocitypowered.api.scheduler.Scheduler;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.serializer.plain.PlainTextComponentSerializer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * 认证决策链的单元测试。
 *
 * <p>覆盖"谁会免密直连、谁必须进认证服"这一核心判断——它是 v2.3.1 引入会话直连后
 * 最容易出错的部分，而正确性又直接关系到"未认证玩家能否被隔离在 limbo 之外"。
 *
 * <p>测试策略：用内存实现驱动 {@link AuthRepository}（接口化后无需真实数据库、
 * 也不必 mock final 类），正版验证通过配置关闭，从而把决策链中的分支逐一隔离出来。
 */
class AuthManagerDecisionTest {

    /** 真实的 AuthMe 哈希样例（密码 pantof），与 {@code PasswordHasherTest} 用的是同一组公开向量。 */
    private static final String AUTHME_HASH_PANTOF =
            "$SHA$c7dedf5a36c4a343$05ae3239eee683872ef1cc9096777bf4b1a72a179709efc17d8bf1603b082065";

    @TempDir
    Path dataDirectory;

    private MikuConfig config;
    private MikuMessages messages;
    private FakeRepository repository;
    private AuthManager authManager;

    @BeforeEach
    void setUp() throws IOException {
        config = loadConfig(true);
        messages = new MikuMessages();
        messages.load(dataDirectory, null);
        repository = new FakeRepository();
        authManager = newAuthManager();
    }

    // ---------------------------------------------------------------------
    // 会话免密判定（v2.3.1 直连逻辑）
    // ---------------------------------------------------------------------

    @Test
    void sameIpSessionMarksDirectEntry() {
        repository.player = Optional.of(offlineAccount("alice", "hash"));
        repository.session = Optional.of(new DatabaseManager.Session("1.2.3.4", Long.MAX_VALUE));

        AuthManager.ModeDecision decision = authManager.decideLoginModeAsync("alice", "1.2.3.4").join();

        assertEquals(AuthManager.LoginMode.OFFLINE, decision.mode(), "会话免密玩家仍按离线模式放行");
        assertTrue(authManager.isSessionVerifiedFor("alice"),
                "同 IP 会话有效时必须打上免密标记，初始调度据此直连目标服");
    }

    @Test
    void differentIpSessionRequiresPassword() {
        repository.player = Optional.of(offlineAccount("alice", "hash"));
        repository.session = Optional.of(new DatabaseManager.Session("9.9.9.9", Long.MAX_VALUE));

        authManager.decideLoginModeAsync("alice", "1.2.3.4").join();

        assertFalse(authManager.isSessionVerifiedFor("alice"),
                "IP 不一致时不得免密（会话的唯一维度就是 IP）");
    }

    @Test
    void noSessionRequiresPassword() {
        repository.player = Optional.of(offlineAccount("alice", "hash"));
        repository.session = Optional.empty();

        authManager.decideLoginModeAsync("alice", "1.2.3.4").join();

        assertFalse(authManager.isSessionVerifiedFor("alice"));
    }

    @Test
    void sessionCheckIsSkippedWhenDisabled() throws IOException {
        config = loadConfig(false);
        authManager = newAuthManager();
        repository.player = Optional.of(offlineAccount("alice", "hash"));
        repository.session = Optional.of(new DatabaseManager.Session("1.2.3.4", Long.MAX_VALUE));

        authManager.decideLoginModeAsync("alice", "1.2.3.4").join();

        assertFalse(authManager.isSessionVerifiedFor("alice"), "session.enabled=false 时不应判定会话");
    }

    @Test
    void nullIpSkipsSessionCheckWithoutError() {
        repository.player = Optional.of(offlineAccount("alice", "hash"));
        repository.session = Optional.of(new DatabaseManager.Session("1.2.3.4", Long.MAX_VALUE));

        AuthManager.ModeDecision decision = authManager.decideLoginModeAsync("alice", null).join();

        assertEquals(AuthManager.LoginMode.OFFLINE, decision.mode());
        assertFalse(authManager.isSessionVerifiedFor("alice"), "取不到来源 IP 时必须保守处理");
    }

    @Test
    void sessionMarkIsCaseInsensitiveAndConsumable() {
        repository.player = Optional.of(offlineAccount("Alice", "hash"));
        repository.session = Optional.of(new DatabaseManager.Session("1.2.3.4", Long.MAX_VALUE));

        authManager.decideLoginModeAsync("Alice", "1.2.3.4").join();

        // 大小写不同的昵称应命中同一标记（内部统一归一化）
        assertTrue(authManager.isSessionVerifiedFor("alice"));
        assertTrue(authManager.isSessionVerifiedFor("ALICE"));
    }

    // ---------------------------------------------------------------------
    // 账号类型判定
    // ---------------------------------------------------------------------

    @Test
    void registeredPremiumAccountDecidesPremiumMode() {
        UUID premiumUuid = UUID.randomUUID();
        repository.player = Optional.of(new StoredPlayer(premiumUuid, "Notch", "notch", "hash",
                StoredPlayer.TYPE_PREMIUM, "1.2.3.4", 0L, "1.2.3.4", 0L));

        AuthManager.ModeDecision decision = authManager.decideLoginModeAsync("Notch", "1.2.3.4").join();

        assertEquals(AuthManager.LoginMode.PREMIUM, decision.mode(),
                "已登记的正版账号应强制正版会话校验（不查 API）");
        assertFalse(authManager.isSessionVerifiedFor("Notch"), "正版路径不涉及会话免密");
    }

    @Test
    void unregisteredPlayerFallsBackToOfflineWhenPremiumDisabled() {
        repository.player = Optional.empty();

        AuthManager.ModeDecision decision = authManager.decideLoginModeAsync("newcomer", "1.2.3.4").join();

        assertEquals(AuthManager.LoginMode.OFFLINE, decision.mode());
        assertFalse(authManager.isSessionVerifiedFor("newcomer"),
                "未注册玩家没有会话可言，必须进认证服注册");
    }

    @Test
    void accountWithoutPasswordIsTreatedAsUnregistered() {
        // 正版玩家自动登记出来的记录没有密码 → 视为未注册（走注册流程）
        repository.player = Optional.of(new StoredPlayer(UUID.randomUUID(), "alice", "alice", null,
                StoredPlayer.TYPE_OFFLINE, "1.2.3.4", 0L, "1.2.3.4", 0L));
        repository.session = Optional.of(new DatabaseManager.Session("1.2.3.4", Long.MAX_VALUE));

        authManager.decideLoginModeAsync("alice", "1.2.3.4").join();

        assertFalse(authManager.isSessionVerifiedFor("alice"),
                "无密码记录不享有会话免密（没有可免密保护的凭据）");
    }

    // ---------------------------------------------------------------------
    // 会话免密放行与续期（完整路径）
    // ---------------------------------------------------------------------

    @Test
    void sessionLoginRenewsExpiryWhenEnabled() throws IOException {
        config = loadConfig(true, true);
        authManager = newAuthManager();
        repository.player = Optional.of(offlineAccount("alice", "hash"));
        repository.session = Optional.of(new DatabaseManager.Session("1.2.3.4", Long.MAX_VALUE));

        authManager.decideLoginModeAsync("alice", "1.2.3.4").join();
        authManager.handleConnected(playerFor("alice"));

        assertNotNull(repository.lastSavedSessionExpiry,
                "开启 renew-on-session-login 时，免密进入应顺延会话");
        assertTrue(repository.lastSavedSessionExpiry
                        > System.currentTimeMillis() + 59 * 60_000L,
                "续期后的过期时间应约为一个完整时长之后");
    }

    @Test
    void sessionLoginDoesNotRenewWhenDisabled() throws IOException {
        config = loadConfig(true, false);
        authManager = newAuthManager();
        repository.player = Optional.of(offlineAccount("alice", "hash"));
        repository.session = Optional.of(new DatabaseManager.Session("1.2.3.4", Long.MAX_VALUE));

        authManager.decideLoginModeAsync("alice", "1.2.3.4").join();
        authManager.handleConnected(playerFor("alice"));

        assertNull(repository.lastSavedSessionExpiry,
                "关闭续期时会话应保持「从上次密码登录起硬性到期」的语义");
    }

    @Test
    void sessionMarkIsConsumedAfterSuccessfulEntry() {
        repository.player = Optional.of(offlineAccount("alice", "hash"));
        repository.session = Optional.of(new DatabaseManager.Session("1.2.3.4", Long.MAX_VALUE));

        authManager.decideLoginModeAsync("alice", "1.2.3.4").join();
        authManager.handleConnected(playerFor("alice"));

        assertFalse(authManager.isSessionVerifiedFor("alice"), "标记用后即删，避免影响后续连接");
    }

    // ---------------------------------------------------------------------
    // Dialog 开关关闭 → 回到聊天栏登录
    // ---------------------------------------------------------------------

    @Test
    void dialogDisabledSendsChatUsageInsteadOfDialog() {
        // dialog.enabled: false 时，落到认证服的离线玩家必须收到聊天栏用法提示，
        // 且绝不能进入静默态（静默只由对话框下发成功触发；一旦误进，
        // 该玩家的所有聊天提示都会被丢弃，而又没有任何对话框按钮能解除它）
        config = loadConfigWithDialog(false);
        authManager = newAuthManager();
        repository.player = Optional.of(offlineAccount("alice", "hash"));

        Player player = playerFor("alice");
        authManager.handleConnected(player, "limbo");

        verify(player, times(1)).sendMessage(chatMessageContaining("/login"));
        verify(player, never()).showTitle(any(net.kyori.adventure.title.Title.class));
        assertFalse(repository.audits.isEmpty(), "关掉对话框不影响认证流程本身");
    }

    @Test
    void dialogDisabledTellsUnregisteredPlayerToRegister() {
        config = loadConfigWithDialog(false);
        authManager = newAuthManager();
        repository.player = Optional.empty();

        Player player = playerFor("newcomer");
        authManager.handleConnected(player, "limbo");

        verify(player, times(1)).sendMessage(chatMessageContaining("/register"));
    }

    @Test
    void dialogEnabledKeepsStartingTheAuthFlow() throws IOException {
        // 对照组：开关保持默认开启时行为不变（仍走原有流程，Title/BossBar 照常显示）
        config = loadConfig(true);
        authManager = newAuthManager();
        repository.player = Optional.of(offlineAccount("alice", "hash"));

        Player player = playerFor("alice");
        authManager.handleConnected(player, "limbo");

        assertTrue(authManager.isTrackedForDisplay(player.getUniqueId()),
                "开关开启时应照常建立 Title/BossBar 跟踪（不因本改动退化）");
    }

    // ---------------------------------------------------------------------
    // 管理员交互式密码输入（避免明文进入命令历史）
    // ---------------------------------------------------------------------

    @Test
    void passwordInputIsConsumedAndNeverBroadcast() {
        Player admin = playerFor("admin");

        authManager.beginPasswordReset(admin, "alice");
        boolean consumed = authManager.consumePasswordInput(admin, "freshSecret123");

        assertTrue(consumed, "★ 必须返回 true——调用方据此阻止该聊天广播，否则密码会泄露给全服");
    }

    @Test
    void passwordInputIsOneShot() {
        Player admin = playerFor("admin");

        authManager.beginPasswordReset(admin, "alice");
        authManager.consumePasswordInput(admin, "freshSecret123");

        assertFalse(authManager.consumePasswordInput(admin, "后续普通聊天"),
                "输入是一次性的，随后的普通聊天不应被误当作密码吞掉");
    }

    @Test
    void chatWithoutPendingResetIsUntouched() {
        assertFalse(authManager.consumePasswordInput(playerFor("someone"), "随便聊聊"),
                "没有等待输入的管理员，聊天必须照常广播");
    }

    // ---------------------------------------------------------------------
    // 改密：必须与登录走同一套哈希识别
    // ---------------------------------------------------------------------

    /**
     * 迁移来的账号（AuthMe 的 {@code $SHA$} 哈希）能登录、也必须能改密。
     *
     * <p>回归点：改密路径曾直接用 BCrypt 校验旧密码，于是这些玩家"能登录却改不了密码"
     * （永远提示当前密码错误），且每次失败都计入跨会话失败计数，最终把自己锁掉。
     */
    @Test
    void changePasswordAcceptsMigratedLegacyHash() {
        repository.player = Optional.of(offlineAccount("alice", AUTHME_HASH_PANTOF));
        repository.session = Optional.of(
                new DatabaseManager.Session("1.2.3.4", Long.MAX_VALUE));

        Player player = playerFor("alice");
        // 会话免密进入：该连接随即处于"已认证"状态，满足 /changepassword 的前置条件
        authManager.decideLoginModeAsync("alice", "1.2.3.4").join();
        authManager.handleConnected(player);
        assertTrue(authManager.isAllowed(player), "会话免密进入后应处于已认证状态");

        authManager.handleChangePasswordCommand(player, "pantof", "brandNewPass1", "brandNewPass1");

        assertTrue(awaitChangePasswordChain(),
                "改密链路应在 5 秒内跑完；超时说明 AuthMe 格式的旧密码未被校验通过");
        assertTrue(repository.sessionCleared, "改密后必须清除该账号的同 IP 会话");
        String written = repository.writtenPasswordHash;
        assertNotNull(written, "旧密码正确时应写入新哈希");
        assertTrue(PasswordHasher.verify("brandNewPass1", written),
                "新哈希应为 BCrypt 且能被校验通过");
    }

    // ---------------------------------------------------------------------
    // 离线玩家落在哪台服务器（认证服隔离边界）
    // ---------------------------------------------------------------------

    /**
     * 落在认证服上的离线玩家，绝不能被"送回"他自己已经在的那台服务器。
     *
     * <p><b>回归点（2026-09-22 线上实测）</b>：{@code ServerConnectedEvent} 发生时
     * {@code player.getCurrentServer()} 还没写回（读到的仍是空的），旧实现据此把
     * "落在认证服"误判成"落在正式服"，于是把玩家送回他已经在的认证服 ——
     * Velocity 以 ALREADY_CONNECTED 拒绝，这个失败又被当成"认证服不可用"，
     * 玩家直接被踢下线。后果是<b>离线玩家永远注册不了、登录不了</b>
     * （正版/基岩/会话免密玩家在前面的分支就返回了，所以问题被掩盖了很久）。
     */
    @Test
    void offlinePlayerLandingOnAuthServerIsNotSentAway() {
        repository.player = Optional.empty();               // 未注册的离线玩家
        Player player = playerFor("newcomer");              // getCurrentServer() 为空，复现该时序
        int before = repository.findPlayerCalls;

        // 事件告诉我们在 limbo（认证服）上 —— 这就是权威答案
        authManager.handleConnected(player, "limbo");

        verify(player, never()).disconnect(any());
        verify(player, never()).createConnectionRequest(any());
        assertTrue(repository.findPlayerCalls > before,
                "应直接进入登录/注册流程（查库决定弹哪个框），而不是被送走");
    }

    /** 确实停在正式服上的离线玩家，仍然要送回认证服（隔离边界不能丢）。 */
    @Test
    void offlinePlayerOnRealServerIsSentToAuthServer() {
        repository.player = Optional.empty();
        RegisteredServer limbo = mock(RegisteredServer.class);
        when(proxy.getServer("limbo")).thenReturn(Optional.of(limbo));

        ConnectionRequestBuilder builder = mock(ConnectionRequestBuilder.class);
        ConnectionRequestBuilder.Result ok = mock(ConnectionRequestBuilder.Result.class);
        when(ok.isSuccessful()).thenReturn(true);
        when(builder.connect()).thenReturn(CompletableFuture.completedFuture(ok));

        Player player = playerFor("newcomer");
        when(player.createConnectionRequest(limbo)).thenReturn(builder);

        authManager.handleConnected(player, "sd");          // 落在正式服 sd 上

        verify(player, times(1)).createConnectionRequest(limbo);
        verify(player, never()).disconnect(any());
    }

    // ---------------------------------------------------------------------
    // 进服诊断：断线原因不得误判为"正版昵称冲突"
    // ---------------------------------------------------------------------

    /**
     * 登录之后的断线不能被写成"正版昵称冲突"。
     *
     * <p><b>回归点（2026-09-22 线上误报）</b>：Velocity 只在 {@code LoginEvent} 触发后才发出
     * {@code DisconnectEvent}，而 {@code LoginEvent} 是会话校验通过之后才触发的 ——
     * 也就是说本方法能看到的事件，本身就意味着"会话校验已经过了"。
     * 旧实现把所有非成功状态都写成"该昵称已确认为正版、会话校验失败"并落到
     * {@code premium-conflicts.log}，实测该文件 16 条记录 100% 是这类误报
     * （目标服不可达、玩家选服前退出），会把管理员引去执行 {@code /mikuauth unbind}。
     */
    @Test
    void disconnectAfterLoginIsNotRecordedAsNameConflict() throws IOException {
        repository.player = Optional.of(premiumAccount("Notch"));
        authManager.decideLoginModeAsync("Notch", "1.2.3.4").join();

        for (DisconnectEvent.LoginStatus status : List.of(
                DisconnectEvent.LoginStatus.PRE_SERVER_JOIN,
                DisconnectEvent.LoginStatus.CANCELLED_BY_PROXY,
                DisconnectEvent.LoginStatus.CANCELLED_BY_USER,
                DisconnectEvent.LoginStatus.CANCELLED_BY_USER_BEFORE_COMPLETE)) {
            authManager.logJoinFailure("Notch", status, "1.2.3.4");
        }
        conflictLog.flush();

        assertEquals(List.of(), conflictLogDataLines(),
                "登录之后的断线（玩家已通过会话校验）与昵称冲突无关，不得写入冲突记录");
    }

    /** 真正的同名冲突（被顶下线）必须留下记录 —— 这是冲突记录文件唯一的使用场景。 */
    @Test
    void duplicateLoginIsRecordedAsNameConflict() throws IOException {
        repository.player = Optional.of(premiumAccount("Notch"));
        authManager.decideLoginModeAsync("Notch", "1.2.3.4").join();

        authManager.logJoinFailure("Notch", DisconnectEvent.LoginStatus.CONFLICTING_LOGIN, "1.2.3.4");
        conflictLog.flush();

        List<String> lines = conflictLogDataLines();
        assertEquals(1, lines.size(), "同名冲突应写入一条记录，实际: " + lines);
        assertTrue(lines.get(0).contains("Notch"), "记录里应包含昵称: " + lines.get(0));
        assertTrue(lines.get(0).contains("同名冲突"), "记录里应写明断开状态: " + lines.get(0));
    }

    /** 离线玩家（持有密码的普通账号）的同样情形也不得写入冲突记录。 */
    @Test
    void offlinePlayerDisconnectIsNotRecordedAsNameConflict() throws IOException {
        repository.player = Optional.of(offlineAccount("alice", "hash"));
        authManager.decideLoginModeAsync("alice", "1.2.3.4").join();

        authManager.logJoinFailure("alice", DisconnectEvent.LoginStatus.PRE_SERVER_JOIN, "1.2.3.4");
        conflictLog.flush();

        assertEquals(List.of(), conflictLogDataLines(), "离线账号的断线与正版昵称冲突无关");
    }

    /** 没有决策记录（例如插件刚加载完、连接来自更早）、基岩版、正常退出：都不应产生任何诊断输出。 */
    @Test
    void unrelatedDisconnectsProduceNoConflictRecord() throws IOException {
        authManager.logJoinFailure("stranger", DisconnectEvent.LoginStatus.PRE_SERVER_JOIN, "1.2.3.4");

        repository.player = Optional.of(offlineAccount("alice", "hash"));
        authManager.decideLoginModeAsync("alice", "1.2.3.4").join();
        authManager.logJoinFailure("alice", DisconnectEvent.LoginStatus.SUCCESSFUL_LOGIN, "1.2.3.4");
        conflictLog.flush();

        assertEquals(List.of(), conflictLogDataLines());
    }

    // ---------------------------------------------------------------------
    // 工具
    // ---------------------------------------------------------------------

    /** 等待异步改密链路（校验 → 写库 → 清会话）跑完。
     *
     * <p>以"会话已清除"作为完成信号：它是链路的最后一步，观察到它时
     * 写库与审计都已经发生。
     */
    private boolean awaitChangePasswordChain() {
        long deadline = System.currentTimeMillis() + 5_000L;
        while (System.currentTimeMillis() < deadline) {
            if (repository.sessionCleared) {
                return true;
            }
            try {
                Thread.sleep(10L);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
        }
        return false;
    }

    /** 构造一个可驱动 handleConnected 的玩家（含远端地址，认证流会取 IP）。 */
    private static Player playerFor(String nickname) {
        Player player = mock(Player.class);
        when(player.getUniqueId()).thenReturn(UUID.randomUUID());
        when(player.getUsername()).thenReturn(nickname);
        when(player.isActive()).thenReturn(true);
        when(player.getRemoteAddress()).thenReturn(new InetSocketAddress("1.2.3.4", 12345));
        when(player.getCurrentServer()).thenReturn(Optional.empty());
        return player;
    }

    /** 写一份最小配置并加载（默认关闭正版验证，避免测试依赖外部 API）。 */
    private MikuConfig loadConfig(boolean sessionEnabled) throws IOException {
        return loadConfig(sessionEnabled, true);
    }

    private MikuConfig loadConfig(boolean sessionEnabled, boolean renewOnLogin) throws IOException {
        return loadConfig(sessionEnabled, renewOnLogin, true);
    }

    /**
     * 写一份最小配置并加载。
     *
     * @param dialogEnabled config.yml 的 {@code dialog.enabled}
     */
    private MikuConfig loadConfigWithDialog(boolean dialogEnabled) {
        try {
            return loadConfig(true, true, dialogEnabled);
        } catch (IOException e) {
            throw new AssertionError("写测试配置失败", e);
        }
    }

    private MikuConfig loadConfig(boolean sessionEnabled, boolean renewOnLogin, boolean dialogEnabled)
            throws IOException {
        // bcrypt-cost 取最低值：测试只需验证"哈希被写入且可校验"，
        // 用默认 cost=10 会让每个涉及哈希的用例多花上百毫秒
        // 认证服名字取 limbo，与线上部署保持一致
        Files.writeString(dataDirectory.resolve("config.yml"), """
                server:
                  auth-server: "limbo"
                premium:
                  enabled: false
                login:
                  bcrypt-cost: 4
                session:
                  enabled: %s
                  renew-on-session-login: %s
                dialog:
                  enabled: %s
                """.formatted(sessionEnabled, renewOnLogin, dialogEnabled), StandardCharsets.UTF_8);
        MikuConfig loaded = new MikuConfig();
        loaded.load(dataDirectory, null);
        return loaded;
    }

    /** 匹配"渲染后文本包含某片段"的聊天消息（MiniMessage 标签已被渲染掉，故不能直接比对原文）。 */
    private static Component chatMessageContaining(String fragment) {
        return org.mockito.ArgumentMatchers.argThat(component -> component != null
                && PlainTextComponentSerializer.plainText().serialize(component).contains(fragment));
    }

    /** 构造可满足转服调度的 ProxyServer（handleConnected 完成认证后会调度转服）。 */
    private ProxyServer schedulableServer() {
        ProxyServer proxy = mock(ProxyServer.class);
        Scheduler scheduler = mock(Scheduler.class);
        Scheduler.TaskBuilder builder = mock(Scheduler.TaskBuilder.class);
        when(proxy.getScheduler()).thenReturn(scheduler);
        when(scheduler.buildTask(any(), any(Runnable.class))).thenReturn(builder);
        when(builder.delay(any(Duration.class))).thenReturn(builder);
        when(builder.repeat(any(Duration.class))).thenReturn(builder);
        when(builder.schedule()).thenReturn(mock(ScheduledTask.class));
        return proxy;
    }

    private ProxyServer proxy;

    /**
     * 冲突记录器：由测试持有，便于 flush 后断言真实落盘内容
     * （record 是异步写盘，直接用 mock 断言会漏掉"写没写进文件"这一层）。
     */
    private PremiumConflictLog conflictLog;

    private AuthManager newAuthManager() {
        proxy = schedulableServer();
        conflictLog = new PremiumConflictLog(dataDirectory, config,
                org.slf4j.helpers.NOPLogger.NOP_LOGGER);
        return new AuthManager(new Object(), proxy,
                org.slf4j.helpers.NOPLogger.NOP_LOGGER,
                config, messages, repository,
                new PremiumService(config, org.slf4j.helpers.NOPLogger.NOP_LOGGER),
                new DialogService(config, messages, org.slf4j.helpers.NOPLogger.NOP_LOGGER),
                new DisplayManager(config, messages),
                new AuditLogger(repository, config, org.slf4j.helpers.NOPLogger.NOP_LOGGER),
                conflictLog,
                new BackendKickLog(dataDirectory, config, org.slf4j.helpers.NOPLogger.NOP_LOGGER));
    }

    /** 读取冲突记录的数据行（跳过以 # 开头的文件头）；文件不存在时视为空。 */
    private List<String> conflictLogDataLines() throws IOException {
        Path file = dataDirectory.resolve(config.premiumConflictLogFile());
        if (Files.notExists(file)) {
            return List.of();
        }
        return Files.readAllLines(file, StandardCharsets.UTF_8).stream()
                .filter(line -> !line.isBlank() && !line.startsWith("#"))
                .toList();
    }

    private static StoredPlayer premiumAccount(String nickname) {
        return new StoredPlayer(UUID.randomUUID(), nickname, nickname.toLowerCase(),
                "$2a$04$0123456789012345678901234567890123456789012345678901",
                StoredPlayer.TYPE_PREMIUM, "1.2.3.4", 0L, "1.2.3.4", 0L);
    }

    private static StoredPlayer offlineAccount(String nickname, String hash) {
        return new StoredPlayer(UUID.randomUUID(), nickname, nickname.toLowerCase(), hash,
                StoredPlayer.TYPE_OFFLINE, "1.2.3.4", 0L, "1.2.3.4", 0L);
    }

    /** 内存仓储：只实现决策链会走到的查询，写入操作一律成功返回。 */
    private static final class FakeRepository implements AuthRepository, AuditRepository {

        private Optional<StoredPlayer> player = Optional.empty();
        private Optional<DatabaseManager.Session> session = Optional.empty();
        /** 最近一次会话写入的过期时间（null = 未写入），用于断言续期行为。 */
        private volatile Long lastSavedSessionExpiry;
        /** 最近一次 updatePassword 写入的哈希（null = 未写入），用于断言改密结果。 */
        private volatile String writtenPasswordHash;
        /** 是否调用过 clearSession（改密/重置密码后应让旧会话立即失效）。 */
        private volatile boolean sessionCleared;
        /** findPlayer 被调用的次数：用于断言"认证流程确实推进到查库这一步"。 */
        private volatile int findPlayerCalls;
        /** 收到的审计记录（便于断言"该记的都记了"）。 */
        private final List<AuditEntry> audits = new java.util.concurrent.CopyOnWriteArrayList<>();

        @Override
        public CompletableFuture<Void> appendAudit(AuditEntry entry) {
            audits.add(entry);
            return CompletableFuture.completedFuture(null);
        }

        @Override
        public CompletableFuture<List<AuditEntry>> findAuditByNickname(String nickname, int limit) {
            return CompletableFuture.completedFuture(List.copyOf(audits));
        }

        @Override
        public CompletableFuture<List<AuditEntry>> findAuditByIp(String ip, int limit) {
            return CompletableFuture.completedFuture(List.copyOf(audits));
        }

        @Override
        public CompletableFuture<Integer> purgeExpiredAudit(long beforeMillis) {
            return CompletableFuture.completedFuture(0);
        }

        @Override
        public CompletableFuture<Optional<StoredPlayer>> findPlayer(String nickname) {
            findPlayerCalls++;
            return CompletableFuture.completedFuture(player);
        }

        @Override
        public CompletableFuture<Optional<StoredPlayer>> findPlayerByUuid(UUID uuid) {
            return CompletableFuture.completedFuture(Optional.empty());
        }

        @Override
        public CompletableFuture<DatabaseManager.RegisterResult> register(
                UUID uuid, String nickname, String passwordHash, String authType, String ip) {
            return CompletableFuture.completedFuture(DatabaseManager.RegisterResult.OK);
        }

        @Override
        public CompletableFuture<DatabaseManager.RegisterResult> registerWithIpLimit(
                UUID uuid, String nickname, String passwordHash, String authType, String ip,
                int maxAccounts) {
            // 配额检查在真实实现里与写入同事务；这里配额不限，直接复用注册路径
            return register(uuid, nickname, passwordHash, authType, ip);
        }

        @Override
        public CompletableFuture<Boolean> renameAccount(UUID uuid, String newNickname) {
            return CompletableFuture.completedFuture(false);
        }

        @Override
        public CompletableFuture<Boolean> releaseStaleAccount(String nickname, UUID expectedUuid) {
            return CompletableFuture.completedFuture(false);
        }

        @Override
        public CompletableFuture<Boolean> updatePassword(String nickname, String passwordHash) {
            writtenPasswordHash = passwordHash;
            return CompletableFuture.completedFuture(true);
        }

        @Override
        public CompletableFuture<Boolean> deletePassword(String nickname) {
            return CompletableFuture.completedFuture(true);
        }

        @Override
        public CompletableFuture<Boolean> clearPremiumBinding(String nickname) {
            return CompletableFuture.completedFuture(false);
        }

        @Override
        public CompletableFuture<Void> finishLogin(String nickname, String ip, long expiresAtMillis) {
            // 与真实实现一致：≤0 表示"本次不写会话"（免密路径），此时不得覆盖
            // 会话续期（renewSessionIfEnabled → saveSession）已经写下的到期时间
            if (expiresAtMillis > 0) {
                lastSavedSessionExpiry = expiresAtMillis;
            }
            return CompletableFuture.completedFuture(null);
        }

        @Override
        public CompletableFuture<Integer> countAccountsByIp(String ip) {
            return CompletableFuture.completedFuture(0);
        }

        @Override
        public CompletableFuture<List<StoredPlayer>> findAccountsByIp(String ip) {
            return CompletableFuture.completedFuture(List.of());
        }

        @Override
        public CompletableFuture<Void> saveSession(String nickname, String ip, long expiresAtMillis) {
            lastSavedSessionExpiry = expiresAtMillis;
            return CompletableFuture.completedFuture(null);
        }

        @Override
        public CompletableFuture<Optional<DatabaseManager.Session>> findSession(String nickname) {
            return CompletableFuture.completedFuture(session);
        }

        @Override
        public CompletableFuture<Void> clearSession(String nickname) {
            sessionCleared = true;
            return CompletableFuture.completedFuture(null);
        }

        @Override
        public CompletableFuture<Integer> purgeExpiredSessions() {
            return CompletableFuture.completedFuture(0);
        }
    }
}
