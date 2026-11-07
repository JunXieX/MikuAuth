package cn.miku.auth.paper;

import cn.miku.auth.audit.AuditAction;
import cn.miku.auth.database.DatabaseManager;
import cn.miku.auth.database.StoredPlayer;
import cn.miku.auth.security.LoginThrottle;
import cn.miku.auth.security.PasswordHasher;
import cn.miku.auth.security.PasswordPolicy;
import cn.miku.auth.util.UuidUtil;
import com.destroystokyo.paper.event.player.PlayerConnectionCloseEvent;
import com.destroystokyo.paper.profile.PlayerProfile;
import io.papermc.paper.connection.PlayerConfigurationConnection;
import io.papermc.paper.dialog.Dialog;
import io.papermc.paper.dialog.DialogResponseView;
import io.papermc.paper.event.connection.configuration.AsyncPlayerConnectionConfigureEvent;
import io.papermc.paper.event.player.PlayerCustomClickEvent;
import io.papermc.paper.registry.data.dialog.ActionButton;
import io.papermc.paper.registry.data.dialog.DialogBase;
import io.papermc.paper.registry.data.dialog.action.DialogAction;
import io.papermc.paper.registry.data.dialog.body.DialogBody;
import io.papermc.paper.registry.data.dialog.input.DialogInput;
import io.papermc.paper.registry.data.dialog.type.DialogType;
import net.kyori.adventure.key.Key;
import net.kyori.adventure.text.Component;
import org.bukkit.Bukkit;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.PlayerJoinEvent;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * 进服前认证闸门：只实现「Pre」模式。
 *
 * <p><b>时序</b>：{@link AsyncPlayerConnectionConfigureEvent} 由 Paper 内部的
 * {@code PaperConfigurationTask} 在「注册表同步完成之后、进世界的最后一步之前」触发，
 * 事件跑在专用虚拟线程上，服务端会等监听器返回才继续这条连接。因此这里可以：
 * <ol>
 *   <li>用 {@link PlayerConfigurationConnection#getAudience()} 把原生对话框发给玩家；</li>
 *   <li>阻塞等待玩家提交（超时由配置决定）；</li>
 *   <li>认证通过就直接返回 —— 连接继续，玩家进入世界；失败则重发对话框或断开。</li>
 * </ol>
 *
 * <p><b>为什么可以阻塞</b>：阻塞的是这名玩家自己的虚拟线程，不占用主线程 tick。
 * 跨线程的账号读写一律走公共层的 {@code DatabaseManager}（内部单线程串行 + 异步返回），
 * 这里只在这条虚拟线程上 {@code join()} 结果，不碰其它玩家的流程。
 *
 * <p><b>三个必须照做的细节</b>（都是 Paper 侧的硬约束，配错就是"框点了没反应"）：
 * <ul>
 *   <li>{@code afterAction = WAIT_FOR_RESPONSE}：默认值是 {@code CLOSE}，点一下按钮客户端就把框关掉，
 *       玩家在校验期间只会看到空屏；{@code WAIT_FOR_RESPONSE} 会切到"等待响应"屏。</li>
 *   <li>结束时必须 {@code closeDialog()}：否则客户端停在"等待响应"屏，玩家进世界后屏幕还是那块。</li>
 *   <li>文本输入必须显式 {@code maxLength}：默认只有 32，超出部分客户端根本不让输入，
 *       于是"代理端注册的长密码"在这边永远登不上。</li>
 * </ul>
 */
public final class PreJoinGate implements Listener {

    /** 提交动作的标识（客户端点击后由 {@link PlayerCustomClickEvent} 带回）。 */
    static final Key SUBMIT = Key.key("mikuauth", "submit");

    /** 对话框协议自 1.21.6（协议号 771）起才有 dialog / custom click 包。 */
    private static final int DIALOG_MIN_PROTOCOL = 771;

    /** 同一 IP 两次提交的最小间隔（毫秒）：每次提交都会算一次 BCrypt，不能连点重算。 */
    private static final long SUBMIT_INTERVAL_MILLIS = 400;
    /** 提交节流表的上限与保留时长（按时间清理，避免随独立 IP 数无限增长）。 */
    private static final int SUBMIT_THROTTLE_MAX_ENTRIES = 4096;
    private static final long SUBMIT_THROTTLE_RETAIN_MILLIS = 60_000L;

    private final MikuAuthPlugin plugin;
    /**
     * 正在配置阶段等待认证的连接。
     *
     * <p>键是连接实例而不是玩家 UUID：同一账号第二次连接（客户端重连、双开）进来时，
     * 用 UUID 做键会覆盖掉前一条仍在等待的会话，前一个虚拟线程就要干等到超时。
     */
    private final ConcurrentHashMap<PlayerConfigurationConnection, Session> sessions = new ConcurrentHashMap<>();
    /** 认证通过时的提示：配置阶段没有聊天栏，留到进世界后补发。 */
    private final ConcurrentHashMap<String, Component> pendingChat = new ConcurrentHashMap<>();
    /** 来源 IP → 上次提交时刻（提交会算一次 BCrypt，不能任其连点重算）。 */
    private final ConcurrentHashMap<String, Long> lastSubmitByIp = new ConcurrentHashMap<>();

    PreJoinGate(MikuAuthPlugin plugin) {
        this.plugin = plugin;
    }

    /** 一条连接的认证会话。 */
    private static final class Session {
        final UUID id;
        final String name;
        final String ip;
        final PlayerConfigurationConnection connection;
        final boolean registering;
        final CompletableFuture<Void> done = new CompletableFuture<>();
        /** 会话是否已有结论（成功 / 断开 / 超时），保证只结算一次。 */
        private final AtomicBoolean finished = new AtomicBoolean();
        /** 一次提交正在处理中：挡住连点。 */
        private final AtomicBoolean working = new AtomicBoolean();
        volatile int tries;

        Session(UUID id, String name, String ip, PlayerConfigurationConnection connection, boolean registering) {
            this.id = id;
            this.name = name;
            this.ip = ip;
            this.connection = connection;
            this.registering = registering;
        }

        boolean finished() {
            return finished.get();
        }

        /** 抢占式结算；返回 true 表示本次调用是唯一的结算者。 */
        boolean finish() {
            return finished.compareAndSet(false, true);
        }

        boolean beginSubmit() {
            return working.compareAndSet(false, true);
        }

        void endSubmit() {
            working.set(false);
        }
    }

    // ------------------------------------------------------------------
    // 闸门
    // ------------------------------------------------------------------

    @EventHandler(priority = EventPriority.NORMAL)
    public void onConfigure(AsyncPlayerConnectionConfigureEvent event) {
        PlayerConfigurationConnection connection = event.getConnection();
        PlayerProfile profile = connection.getProfile();
        String name = profile == null ? null : profile.getName();
        if (name == null || name.isEmpty()) {
            fail(connection, "kick.auth-error", Map.of());
            return;
        }
        // 低于 1.21.6 的客户端收不到对话框包：与其让他在空屏上干等一分钟，不如直接说明原因
        if (!clientSupportsDialog(profile.getId())) {
            fail(connection, "kick.no-dialog-client", Map.of());
            return;
        }
        String ip = addressOf(connection);
        // 被封禁的 IP/账号在弹框之前就拒绝，避免白送一次哈希计算
        LoginThrottle.Lock lock = plugin.throttle().check(ip, name);
        if (lock != null) {
            fail(connection, "error.locked", Map.of("minutes", String.valueOf(lock.remainingMinutes())));
            return;
        }

        Optional<StoredPlayer> account = findAccount(name);
        if (account == null) {
            // 数据库不可用：连该弹登录框还是注册框都判不出来，直接说明情况
            fail(connection, "kick.auth-error", Map.of());
            return;
        }
        boolean registering = account.map(player -> !player.hasPassword()).orElse(true);
        Session session = new Session(profile.getId(), name, ip, connection, registering);
        sessions.put(connection, session);
        try {
            showDialog(session, null);
            // 阻塞到提交成功 / 超次断开 / 超时；服务端在此期间不会让玩家进入世界
            session.done.get(plugin.config().preAuthTimeoutSeconds(), TimeUnit.SECONDS);
        } catch (TimeoutException timeout) {
            if (session.finish()) {
                plugin.audit().record(AuditAction.KICK_TIMEOUT, name, profile.getId(), ip, "配置阶段认证超时");
                fail(connection, "kick.auth-timeout", Map.of());
            }
        } catch (Exception e) {
            plugin.log().warn("[认证] {} 的配置阶段认证异常: {}", name, e.toString());
            if (session.finish()) {
                fail(connection, "kick.auth-error", Map.of());
            }
        } finally {
            session.finish();
            sessions.remove(connection);
            // 无论结果如何都要把客户端的对话框收掉（成功时是"等待响应"屏）
            closeQuietly(connection);
        }
    }

    /** 对话框提交（自定义点击）。事件在主线程触发，因此这里只解析参数，校验与落库全部异步。 */
    @EventHandler(priority = EventPriority.NORMAL)
    public void onCustomClick(PlayerCustomClickEvent event) {
        if (!SUBMIT.equals(event.getIdentifier())) {
            return;
        }
        if (!(event.getCommonConnection() instanceof PlayerConfigurationConnection connection)) {
            return;
        }
        Session session = sessions.get(connection);
        if (session == null || session.finished()) {
            return;
        }
        DialogResponseView view = event.getDialogResponseView();
        // 客户端把每个输入的当前值按 key 塞进同一个 compound 回传（Paper 的 dialog 协议约定）
        String password = view == null ? null : view.getText("password");
        String confirm = view == null ? null : view.getText("confirm");
        if (password == null) {
            // 排障锚点：点得到按钮但拿不到输入值时，日志直接指认是"没有 payload"还是"缺字段"
            plugin.log().warn("[认证] {} 的对话框提交缺少 password，payload={}", session.name,
                    view == null ? "<无响应数据>" : view.payload().string());
        }
        if (!allowSubmit(session.ip)) {
            // 同 IP 提交过快：这一次不算哈希，但必须把对话框重画一遍 ——
            // 客户端点了按钮就切到"等待响应"屏，静默丢弃会让它停在那里直到超时被断开
            showDialog(session, null);
            return;
        }
        if (!session.beginSubmit()) {
            return;
        }
        boolean registering = session.registering;
        // BCrypt 是 CPU 密集的、SQLite 是文件 IO：都不能压在主线程（这条事件就在主线程）
        runAsync(() -> {
            try {
                if (registering) {
                    submitRegister(session, password, confirm);
                } else {
                    submitLogin(session, password);
                }
            } catch (RuntimeException e) {
                plugin.log().warn("[认证] {} 的提交处理异常: {}", session.name, e.toString());
                retry(session, "error.server-busy", Map.of());
            } finally {
                session.endSubmit();
            }
        });
    }

    /** 玩家在对话框阶段掉线：唤醒还在等待的虚拟线程，别让它干等到超时。 */
    @EventHandler(priority = EventPriority.MONITOR)
    public void onConnectionClose(PlayerConnectionCloseEvent event) {
        if (sessions.isEmpty()) {
            return;
        }
        for (Map.Entry<PlayerConfigurationConnection, Session> entry : sessions.entrySet()) {
            if (!entry.getKey().isConnected()) {
                entry.getValue().finish();
                entry.getValue().done.complete(null);
                sessions.remove(entry.getKey(), entry.getValue());
            }
        }
    }

    /** 认证通过时的提示在配置阶段发不出去，等玩家真正进世界再补。 */
    @EventHandler(priority = EventPriority.MONITOR)
    public void onPlayerJoin(PlayerJoinEvent event) {
        if (pendingChat.isEmpty()) {
            return;
        }
        Component message = pendingChat.remove(event.getPlayer().getName().toLowerCase(Locale.ROOT));
        if (message != null) {
            event.getPlayer().sendMessage(message);
        }
    }

    // ------------------------------------------------------------------
    // 提交处理（与代理端同一套策略与提示）
    // ------------------------------------------------------------------

    private void submitRegister(Session session, String password, String confirm) {
        PasswordPolicy.Violation violation = PasswordPolicy.check(plugin.config(), password);
        if (violation != null) {
            retry(session, violation.messageKey(), violation.placeholders());
            return;
        }
        if (!password.equals(confirm)) {
            retry(session, "error.password-mismatch", Map.of());
            return;
        }
        String hash;
        try {
            hash = PasswordHasher.hash(password, plugin.config().bcryptCost());
        } catch (RuntimeException e) {
            plugin.log().warn("[注册] {} 的密码哈希失败: {}", session.name, e.toString());
            retry(session, "error.server-busy", Map.of());
            return;
        }
        DatabaseManager.RegisterResult result;
        try {
            result = plugin.db().registerWithIpLimit(UuidUtil.offlineUuid(session.name), session.name, hash,
                    StoredPlayer.TYPE_OFFLINE, session.ip, plugin.config().maxAccountsPerIp()).join();
        } catch (RuntimeException e) {
            plugin.log().warn("[注册] {} 写库失败: {}", session.name, e.toString());
            retry(session, "error.server-busy", Map.of());
            return;
        }
        switch (result) {
            case OK -> succeed(session, "auth.success.register", AuditAction.REGISTER, "注册并登录（进服前）");
            case DUPLICATE -> {
                // 占用该昵称的若是"没有密码"的记录（正版自动登记 / deletepassword 遗留），
                // 直接补密码完成注册；否则这条昵称会一直卡在"请注册 → 已被注册"之间
                if (!claimExisting(session, hash)) {
                    retry(session, "error.already-registered", Map.of());
                }
            }
            case IP_LIMIT -> {
                // 认领已有记录不占新名额：删过密码的账号重新注册时，该 IP 的名额可能已经满了，
                // 先按"认领"处理，认领不到才按超限拒绝
                if (!claimExisting(session, hash)) {
                    plugin.audit().record(AuditAction.REJECT_IP_LIMIT, session.name, session.id, session.ip,
                            "该 IP 名下账号数已达上限 " + plugin.config().maxAccountsPerIp());
                    retry(session, "error.ip-limit", Map.of());
                }
            }
            default -> retry(session, "error.server-busy", Map.of());
        }
    }

    private void submitLogin(Session session, String password) {
        if (password == null || password.isEmpty()) {
            retry(session, "error.password-empty", Map.of());
            return;
        }
        Optional<StoredPlayer> account = findAccount(session.name);
        if (account == null) {
            retry(session, "error.server-busy", Map.of());
            return;
        }
        if (account.isEmpty() || !account.get().hasPassword()) {
            retry(session, "error.not-registered", Map.of());
            return;
        }
        String stored = account.get().passwordHash();
        boolean verified;
        try {
            verified = PasswordHasher.verify(password, stored);
        } catch (RuntimeException e) {
            verified = false;
        }
        if (verified) {
            // 迁移来的旧算法在首次成功登录时就地升级为 BCrypt，玩家无感
            if (PasswordHasher.needsUpgrade(stored)) {
                try {
                    String upgraded = PasswordHasher.hash(password, plugin.config().bcryptCost());
                    plugin.db().updatePassword(session.name, upgraded).join();
                    plugin.log().info("[登录] {} 的密码哈希已升级为 BCrypt", session.name);
                } catch (RuntimeException e) {
                    plugin.log().warn("[登录] {} 的哈希升级失败: {}", session.name, e.toString());
                }
            }
            succeed(session, "auth.success.login", AuditAction.LOGIN_SUCCESS, "密码登录（进服前）");
            return;
        }
        session.tries++;
        // 跨会话计数：即使玩家重连，失败次数依然累计
        LoginThrottle.Lock lock = plugin.throttle().recordFailure(session.ip, session.name);
        plugin.audit().record(AuditAction.LOGIN_FAIL, session.name, session.id, session.ip,
                "密码错误（本次连接第 " + session.tries + " 次）" + (lock != null ? "，已触发临时封禁" : ""));
        if (lock != null) {
            if (session.finish()) {
                fail(session.connection, "error.locked",
                        Map.of("minutes", String.valueOf(lock.remainingMinutes())));
                session.done.complete(null);
            }
            return;
        }
        // max-tries: 0 = 不限（与代理端同一口径）；不排除 0 的话，第一次输错就会命中"超过次数"
        int maxTries = plugin.config().maxLoginTries();
        if (maxTries > 0 && session.tries >= maxTries) {
            if (session.finish()) {
                fail(session.connection, "kick.too-many-tries", Map.of());
                session.done.complete(null);
            }
            return;
        }
        retry(session, "error.password-wrong", Map.of());
    }

    /** 认证通过：记审计 + 放行（返回后连接继续，玩家进入世界）。 */
    private void succeed(Session session, String messageKey, AuditAction action, String detail) {
        if (!session.finish()) {
            return;
        }
        plugin.throttle().resetAccount(session.name);
        try {
            // 纸端不做同 IP 会话免密（每次进服都要认证），因此会话有效期传 0
            plugin.db().finishLogin(session.name, session.ip, 0L).join();
        } catch (RuntimeException e) {
            plugin.log().warn("[登录] {} 记录最近登录失败（不影响本次放行）: {}", session.name, e.toString());
        }
        plugin.audit().record(action, session.name, session.id, session.ip, detail);
        // 配置阶段没有聊天栏：Audience#sendMessage 在那里是空实现，存起来等进世界补发
        pendingChat.put(session.name.toLowerCase(Locale.ROOT),
                plugin.messages().component(messageKey + ".chat", Map.of("player", session.name)));
        session.done.complete(null);
    }

    /**
     * 同 IP 提交准入：两次提交至少间隔 {@link #SUBMIT_INTERVAL_MILLIS}。
     *
     * <p>每次提交都会算一次 BCrypt（cost=10 约 100ms CPU），没有准入时一条连接循环点提交
     * 就能持续占满一个核，多开几条连接还能放大。口径与代理端"同 IP 400ms"保持一致；
     * 取不到 IP（理论上的本地/代理场景）时放行，不能让取不到地址把正常玩家挡在门外。
     */
    private boolean allowSubmit(String ip) {
        if (ip == null || ip.isEmpty()) {
            return true;
        }
        long now = System.currentTimeMillis();
        Long previous = lastSubmitByIp.get(ip);
        // 先判后写：被拒的点击不刷新时间戳。否则连点会一直把窗口往后推，
        // 玩家越急着点越永远轮不到自己（代理端 tryAcquireCryptoSlot 也是这个顺序）
        if (previous != null && now - previous < SUBMIT_INTERVAL_MILLIS) {
            return false;
        }
        lastSubmitByIp.put(ip, now);
        if (lastSubmitByIp.size() > SUBMIT_THROTTLE_MAX_ENTRIES) {
            lastSubmitByIp.values().removeIf(at -> now - at > SUBMIT_THROTTLE_RETAIN_MILLIS);
        }
        return true;
    }

    /** 认领"存在但无密码"的旧记录，成功即完成注册并放行。 */
    private boolean claimExisting(Session session, String hash) {
        if (!claimPasswordless(session, hash)) {
            return false;
        }
        succeed(session, "auth.success.register", AuditAction.REGISTER, "注册并登录（认领原有账号，进服前）");
        return true;
    }

    /** 尝试给"存在但无密码"的账号补上密码；数据库故障一律按"未认领"处理。 */
    private boolean claimPasswordless(Session session, String hash) {
        try {
            return plugin.db().claimPasswordless(session.name, hash, session.ip).join();
        } catch (RuntimeException e) {
            plugin.log().warn("[注册] {} 认领无密码账号失败: {}", session.name, e.toString());
            return false;
        }
    }

    private void retry(Session session, String errorKey, Map<String, String> placeholders) {
        if (session.finished()) {
            return;
        }
        showDialog(session, plugin.messages().component(errorKey, placeholders));
    }

    // ------------------------------------------------------------------
    // 对话框
    // ------------------------------------------------------------------

    private void showDialog(Session session, Component errorLine) {
        // 发包线程不敏感，但对话框构建会碰服务端注册表，统一回主线程做
        if (Bukkit.isPrimaryThread()) {
            draw(session, errorLine);
        } else {
            runOnMain(() -> draw(session, errorLine));
        }
    }

    private void draw(Session session, Component errorLine) {
        try {
            session.connection.getAudience().showDialog(buildDialog(session, errorLine));
        } catch (Throwable t) {
            // 对话框发不出去等于玩家永远没法认证：立刻收尾，别让他干等超时
            plugin.log().warn("[认证] {} 的对话框发送失败: {}", session.name, t.toString());
            if (session.finish()) {
                fail(session.connection, "kick.auth-error", Map.of());
                session.done.complete(null);
            }
        }
    }

    private Dialog buildDialog(Session session, Component errorLine) {
        var config = plugin.config();
        String base = session.registering ? "dialog.register" : "dialog.login";
        Map<String, String> placeholders = Map.of(
                "player", session.name,
                "seconds", String.valueOf(config.preAuthTimeoutSeconds()));

        Component body = plugin.messages().component(base + ".body", placeholders);
        if (errorLine != null) {
            // 错误行必须传入已渲染的组件：它的原文是 MiniMessage（messages.yml 里带 <red> 等标签），
            // 用 Component.text 拼会把标签当字面量显示给玩家
            body = Component.text().append(body).append(Component.newline())
                    .append(plugin.messages().component("prefix")).append(errorLine).build();
        }
        // 文本框上限必须跟着注册策略走：Paper 的默认值只有 32，配置放宽后
        // 玩家根本输不进第 33 个字符，代理端注册的长密码账号会永久登录失败
        int maxLength = Math.max(config.minPasswordLength(), config.maxPasswordLength());
        List<DialogInput> inputs = new ArrayList<>(session.registering ? 2 : 1);
        inputs.add(DialogInput.text("password",
                        plugin.messages().component(base + ".input-label", placeholders))
                .maxLength(maxLength)
                .build());
        if (session.registering) {
            inputs.add(DialogInput.text("confirm",
                            plugin.messages().component(base + ".confirm-label", placeholders))
                    .maxLength(maxLength)
                    .build());
        }

        DialogBase dialogBase = DialogBase.builder(plugin.messages().component(base + ".title", placeholders))
                .canCloseWithEscape(config.dialogCanCloseWithEscape())
                .pause(false)                              // 单人游戏才有意义，服务器上显式关掉
                .afterAction(DialogBase.DialogAfterAction.WAIT_FOR_RESPONSE)
                .body(List.of(DialogBody.plainMessage(body)))
                .inputs(inputs)
                .build();

        ActionButton button = ActionButton.builder(plugin.messages().component(base + ".button", placeholders))
                .tooltip(plugin.messages().component(base + ".button-tooltip", placeholders))
                .width(160)
                // additions 传 null：这个形参是"待解析的 NBT"，非 null 时 Paper 会先解析成 Tag
                // 再断言必须是 compound，传字符串会被当成 SNBT 解析出 string tag 直接抛异常。
                // 登录/注册由服务端会话决定，不需要附加数据；玩家填的输入值由客户端并入回传的 compound。
                .action(DialogAction.customClick(SUBMIT, null))
                .build();

        return Dialog.create(factory -> factory.empty()
                .base(dialogBase)
                .type(DialogType.multiAction(List.of(button)).columns(1).build()));
    }

    // ------------------------------------------------------------------
    // 工具
    // ------------------------------------------------------------------

    /** 查账号；数据库故障返回 null（与"查无此人"区分开）。 */
    private Optional<StoredPlayer> findAccount(String name) {
        try {
            return plugin.db().findPlayer(name).join();
        } catch (RuntimeException e) {
            plugin.log().warn("[认证] {} 的账号查询失败: {}", name, e.toString());
            return null;
        }
    }

    /** 断开并附上提示（配置阶段只能靠断开画面传达信息）。 */
    private void fail(PlayerConfigurationConnection connection, String key, Map<String, String> placeholders) {
        try {
            connection.disconnect(plugin.messages().component(key, placeholders));
        } catch (Throwable t) {
            plugin.log().warn("[认证] 断开连接时出错: {}", t.toString());
        }
    }

    private static void closeQuietly(PlayerConfigurationConnection connection) {
        try {
            if (connection.isConnected()) {
                connection.getAudience().closeDialog();
            }
        } catch (Throwable ignored) {
            // 连接已经在关闭流程里，关框失败没有影响
        }
    }

    private void runOnMain(Runnable action) {
        try {
            plugin.getServer().getGlobalRegionScheduler().execute(plugin, action);
        } catch (RuntimeException e) {
            // 调度器已关闭时直接执行，至少不会让会话悬挂
            action.run();
        }
    }

    private void runAsync(Runnable action) {
        try {
            plugin.getServer().getAsyncScheduler().runNow(plugin, task -> action.run());
        } catch (RuntimeException e) {
            action.run();
        }
    }

    /**
     * 客户端是否会渲染对话框。
     *
     * <p>原生服务端不装协议转换插件时版本不可能低于服务端，无需判断；装了 ViaVersion
     * 才有老客户端进来的可能，这时按协议号决定：低于 771（1.21.6）收不到对话框包。
     */
    private static boolean clientSupportsDialog(UUID playerId) {
        try {
            if (Bukkit.getPluginManager().getPlugin("ViaVersion") == null) {
                return true;
            }
            Class<?> apiClass = Class.forName("com.viaversion.viaversion.api.ViaAPI");
            Object api = Class.forName("com.viaversion.viaversion.api.Via").getMethod("getAPI").invoke(null);
            int protocol = (int) apiClass.getMethod("getPlayerVersion", UUID.class).invoke(api, playerId);
            // ViaVersion 对"尚未登记该玩家"返回 -1：那代表版本未知，按"支持"处理，
            // 只有明确拿到低于门槛的正数才判定为低版本（否则会把正常客户端误踢）
            return protocol <= 0 || protocol >= DIALOG_MIN_PROTOCOL;
        } catch (Throwable ignored) {
            // 反射失败按"支持"处理：宁可弹一个可能不显示的框，也不要误踢正常客户端
            return true;
        }
    }

    private static String addressOf(PlayerConfigurationConnection connection) {
        try {
            var address = connection.getClientAddress();
            return address == null ? null : address.getHostString();
        } catch (Throwable t) {
            return null;
        }
    }
}
