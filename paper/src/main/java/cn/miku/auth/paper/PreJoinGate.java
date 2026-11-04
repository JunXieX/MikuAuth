package cn.miku.auth.paper;

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
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * 进服前认证闸门：只实现「Pre」模式。
 *
 * <p><b>时序</b>：{@link AsyncPlayerConnectionConfigureEvent} 由 Paper 内部的
 * {@code PaperConfigurationTask} 在「注册表同步完成之后、{@code PrepareSpawnTask}（进世界的最后一步）之前」
 * 触发，事件本身跑在专用虚拟线程上，服务端会等监听器返回才继续这条连接
 * （见 Paper 侧 {@code PaperConfigurationTask#start}：{@code event.callEvent()} 之后才
 * {@code finishCurrentTask}）。因此这里可以：
 * <ol>
 *   <li>用 {@link PlayerConfigurationConnection#getAudience()} 把原生对话框发给玩家；</li>
 *   <li>阻塞等待玩家提交（超时由配置决定）；</li>
 *   <li>认证通过就直接返回 —— 连接继续，玩家进入世界；失败则重发对话框或断开。</li>
 * </ol>
 *
 * <p><b>为什么可以阻塞</b>：阻塞的是这名玩家自己的虚拟线程，不占用主线程 tick；
 * 虚拟线程阻塞几乎不消耗资源，几十人同时挂着也不会撑爆线程池。超时必须有界，否则连接会永久悬挂。
 *
 * <p><b>三个必须照做的细节</b>（都是 Paper 侧的硬约束，配错就是"框点了没反应"）：
 * <ul>
 *   <li>{@code afterAction = WAIT_FOR_RESPONSE}：默认值是 {@code CLOSE}，点一下按钮客户端就把框关掉，
 *       玩家在校验期间只会看到空屏；{@code WAIT_FOR_RESPONSE} 会切到"等待响应"屏，再由服务端
 *       关框或换框，反馈才不会丢。</li>
 *   <li>结束时必须 {@code closeDialog()}：否则客户端停在"等待响应"屏，玩家进世界后屏幕还是那块。</li>
 *   <li>文本输入必须显式 {@code maxLength}：默认只有 32，超出部分客户端根本不让输入，
 *       于是"代理端注册的长密码"在这边永远登不上。</li>
 * </ul>
 *
 * <p><b>只支持一种模式</b>：不做"进服后冻结再登录"的 Post 模式 —— 服务端一旦让玩家进入世界，
 * 就无法在不接管实体的情况下保证他看不到地形。
 */
public final class PreJoinGate implements Listener {

    /** 提交动作的标识（客户端点击后由 {@link PlayerCustomClickEvent} 带回）。 */
    static final Key SUBMIT = Key.key("mikuauth", "submit");

    /** 对话框协议自 1.21.6（协议号 771）起才有 custom click / dialog 包。 */
    private static final int DIALOG_MIN_PROTOCOL = 771;

    private final MikuAuthPlugin plugin;
    /** 跨连接的失败计数与临时封禁（断线重连绕不过去）。 */
    private final Throttle throttle;
    /**
     * 正在配置阶段等待认证的连接。
     *
     * <p>键是连接实例而不是玩家 UUID：同一账号第二次连接（客户端重连、双开）进来时，
     * 用 UUID 做键会覆盖掉前一条仍在等待的会话，前一个虚拟线程就要干等到超时。
     */
    private final ConcurrentHashMap<PlayerConfigurationConnection, Session> sessions = new ConcurrentHashMap<>();
    /** 认证通过时的提示：配置阶段没有聊天栏，留到进世界后补发。 */
    private final ConcurrentHashMap<String, Component> pendingChat = new ConcurrentHashMap<>();

    PreJoinGate(MikuAuthPlugin plugin) {
        this.plugin = plugin;
        this.throttle = new Throttle(plugin.config());
    }

    /** 供主类心跳调用：清理过期计数。 */
    void tick() {
        throttle.purge();
    }

    /** 管理员解锁（玩家名或 IP）。 */
    boolean unlock(String subject) {
        return throttle.unlock(subject);
    }

    /** 一条连接的认证会话。 */
    private static final class Session {
        final UUID id;
        final String name;
        final String ip;
        final PlayerConfigurationConnection connection;
        final String textKey;
        final CompletableFuture<Void> done = new CompletableFuture<>();
        /** 会话是否已有结论（成功 / 断开 / 超时），保证只结算一次。 */
        private final AtomicBoolean finished = new AtomicBoolean();
        /** 一次提交正在处理中：挡住连点。 */
        private final AtomicBoolean working = new AtomicBoolean();
        volatile int tries;

        Session(UUID id, String name, String ip, PlayerConfigurationConnection connection, String textKey) {
            this.id = id;
            this.name = name;
            this.ip = ip;
            this.connection = connection;
            this.textKey = textKey;
        }

        boolean registering() {
            return "register".equals(textKey);
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
            fail(connection, "kick.internal-error");
            return;
        }
        // 低于 1.21.6 的客户端收不到对话框包：与其让他在空屏上干等一分钟，不如直接说明原因
        if (!clientSupportsDialog(profile.getId())) {
            fail(connection, "kick.no-dialog-client");
            return;
        }
        String ip = addressOf(connection);
        // 被封禁的 IP/账号在弹框之前就拒绝，避免白送一次哈希计算
        Throttle.Lock lock = throttle.check(ip, name);
        if (lock != null) {
            fail(connection, "kick.locked", Map.of("minutes", String.valueOf(lock.minutes())));
            return;
        }
        Store.Account account = plugin.store().find(name);
        String textKey = account != null && account.hasPassword() ? "login" : "register";
        Session session = new Session(profile.getId(), name, ip, connection, textKey);
        sessions.put(connection, session);
        try {
            showDialog(session, null);
            // 阻塞到提交成功 / 超次断开 / 超时；服务端在此期间不会让玩家进入世界
            session.done.get(plugin.config().timeoutSeconds(), TimeUnit.SECONDS);
        } catch (TimeoutException timeout) {
            if (session.finish()) {
                fail(connection, "kick.timeout");
            }
        } catch (Exception e) {
            plugin.getLogger().warning("[认证] " + name + " 的配置阶段认证异常: " + e);
            if (session.finish()) {
                fail(connection, "kick.internal-error");
            }
        } finally {
            session.finish();
            sessions.remove(connection);
            // 无论结果如何都要把客户端的对话框收掉（成功时是"等待响应"屏）
            closeQuietly(connection);
        }
    }

    /** 对话框提交（自定义点击）。事件可能在主线程触发，因此这里只解析参数，校验与落库全部异步。 */
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
            // 这一行是排障锚点：点得到按钮但拿不到输入值时，日志能直接指认是"没有 payload"
            // 还是"payload 里没有 password 字段"，不用再猜客户端行为
            plugin.getLogger().warning("[认证] " + session.name + " 的对话框提交缺少 password，payload="
                    + (view == null ? "<无响应数据>" : view.payload().string()));
        }
        if (!session.beginSubmit()) {
            return;
        }
        boolean register = session.registering();
        // BCrypt 校验是 CPU 密集的、SQLite 是文件 IO，都不能压在主线程上（这条事件就在主线程）
        runAsync(() -> {
            try {
                if (register) {
                    submitRegister(session, password, confirm);
                } else {
                    submitLogin(session, password);
                }
            } catch (RuntimeException e) {
                plugin.getLogger().warning("[认证] " + session.name + " 的提交处理异常: " + e);
                retry(session, plugin.messages().raw("error.server-busy"), Map.of());
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
        Crypto.Violation violation = Crypto.check(plugin.config(), password);
        if (violation != null) {
            retry(session, plugin.messages().raw(violation.messageKey()), violation.placeholders());
            return;
        }
        if (!password.equals(confirm)) {
            retry(session, plugin.messages().raw("error.password-mismatch"), Map.of());
            return;
        }
        String hash;
        try {
            hash = Crypto.hash(password, plugin.config().bcryptCost());
        } catch (RuntimeException e) {
            plugin.getLogger().warning("[注册] " + session.name + " 的密码哈希失败: " + e.getMessage());
            retry(session, plugin.messages().raw("error.server-busy"), Map.of());
            return;
        }
        Store.Result result = plugin.store().register(Crypto.offlineUuid(session.name), session.name,
                hash, session.ip, plugin.config().maxAccountsPerIp());
        switch (result) {
            case OK -> succeed(session, "auth.success.register", "REGISTER", "注册并登录（进服前）");
            case DUPLICATE -> retry(session, plugin.messages().raw("error.already-registered"), Map.of());
            case IP_LIMIT -> {
                plugin.store().audit(session.name, session.id, session.ip, "REJECT_IP_LIMIT",
                        "该 IP 名下账号数已达上限 " + plugin.config().maxAccountsPerIp());
                retry(session, plugin.messages().raw("error.ip-limit"), Map.of());
            }
            default -> retry(session, plugin.messages().raw("error.server-busy"), Map.of());
        }
    }

    private void submitLogin(Session session, String password) {
        if (password == null || password.isEmpty()) {
            retry(session, plugin.messages().raw("error.password-empty"), Map.of());
            return;
        }
        Store.Account account = plugin.store().find(session.name);
        if (account == null || !account.hasPassword()) {
            retry(session, plugin.messages().raw("error.not-registered"), Map.of());
            return;
        }
        boolean verified;
        try {
            verified = Crypto.verify(password, account.passwordHash());
        } catch (RuntimeException e) {
            verified = false;
        }
        if (verified) {
            // 迁移来的旧算法在首次成功登录时就地升级为 BCrypt，玩家无感
            if (Crypto.needsUpgrade(account.passwordHash())) {
                try {
                    plugin.store().updatePassword(session.name, Crypto.hash(password, plugin.config().bcryptCost()));
                    plugin.getLogger().info("[登录] " + session.name + " 的密码哈希已升级为 BCrypt");
                } catch (RuntimeException e) {
                    plugin.getLogger().warning("[登录] " + session.name + " 的哈希升级失败: " + e.getMessage());
                }
            }
            succeed(session, "auth.success.login", "LOGIN_SUCCESS", "密码登录（进服前）");
            return;
        }
        session.tries++;
        // 跨会话计数：即使玩家重连，失败次数依然累计
        Throttle.Lock lock = throttle.recordFailure(session.ip, session.name);
        plugin.store().audit(session.name, session.id, session.ip, "LOGIN_FAIL",
                "密码错误（本次连接第 " + session.tries + " 次）"
                        + (lock != null ? "，已触发临时封禁" : ""));
        if (lock != null) {
            if (session.finish()) {
                session.connection.disconnect(plugin.messages().component("kick.locked",
                        Map.of("minutes", String.valueOf(lock.minutes()))));
                session.done.complete(null);
            }
            return;
        }
        if (session.tries >= plugin.config().maxTries()) {
            if (session.finish()) {
                session.connection.disconnect(plugin.messages().component("kick.too-many-tries"));
                session.done.complete(null);
            }
            return;
        }
        retry(session, plugin.messages().raw("error.password-wrong"), Map.of());
    }

    /** 认证通过：记审计 + 放行（返回后连接继续，玩家进入世界）。 */
    private void succeed(Session session, String messageKey, String action, String detail) {
        if (!session.finish()) {
            return;
        }
        throttle.reset(session.name);
        plugin.store().finishLogin(session.name, session.ip);
        plugin.store().audit(session.name, session.id, session.ip, action, detail);
        // Audience#sendMessage 在配置阶段的实现是空方法（PaperPlayerConfigurationConnection 没有覆写它），
        // 直接发等于丢弃；存起来等 PlayerJoinEvent 补发。
        pendingChat.put(session.name.toLowerCase(Locale.ROOT),
                plugin.messages().component(messageKey + ".chat", Map.of("player", session.name)));
        session.done.complete(null);
    }

    /** 失败：把错误拼进正文后重发同一个对话框。 */
    private void retry(Session session, String errorRaw, Map<String, String> placeholders) {
        if (session.finished()) {
            return;
        }
        showDialog(session, render(errorRaw, placeholders));
    }

    private void showDialog(Session session, String errorLine) {
        // 发包线程不敏感，但对话框构建会碰服务端注册表，统一回主线程做，避免跨线程访问注册表
        if (Bukkit.isPrimaryThread()) {
            draw(session, errorLine);
        } else {
            runOnMain(() -> draw(session, errorLine));
        }
    }

    private void draw(Session session, String errorLine) {
        try {
            session.connection.getAudience().showDialog(buildDialog(session, errorLine));
        } catch (Throwable t) {
            // 对话框发不出去等于玩家永远没法认证：立刻收尾，别让他干等超时
            plugin.getLogger().warning("[认证] " + session.name + " 的对话框发送失败: " + t);
            if (session.finish()) {
                fail(session.connection, "kick.internal-error");
                session.done.complete(null);
            }
        }
    }

    private Dialog buildDialog(Session session, String errorLine) {
        var config = plugin.config();
        boolean register = session.registering();
        String base = register ? "dialog.register" : "dialog.login";
        Map<String, String> placeholders = Map.of(
                "player", session.name,
                "seconds", String.valueOf(config.timeoutSeconds()));

        Component body = plugin.messages().component(base + ".body", placeholders);
        if (errorLine != null && !errorLine.isEmpty()) {
            body = Component.text().append(body).append(Component.newline())
                    .append(plugin.messages().component("prefix")).append(Component.text(errorLine)).build();
        }
        // 文本框上限必须跟着注册策略走：Paper 的默认值只有 32，配置放宽到 64 时
        // 玩家根本输不进第 33 个字符，代理端注册的账号会永久登录失败
        int maxLength = Math.max(config.minPasswordLength(), config.maxPasswordLength());
        List<DialogInput> inputs = new ArrayList<>(register ? 2 : 1);
        inputs.add(DialogInput.text("password",
                        plugin.messages().component(base + ".input-label", placeholders))
                .maxLength(maxLength)
                .build());
        if (register) {
            inputs.add(DialogInput.text("confirm",
                            plugin.messages().component(base + ".confirm-label", placeholders))
                    .maxLength(maxLength)
                    .build());
        }

        DialogBase dialogBase = DialogBase.builder(plugin.messages().component(base + ".title", placeholders))
                .canCloseWithEscape(config.allowCloseWithEscape())
                .pause(false)                              // 单人游戏才有意义，服务器上显式关掉
                .afterAction(DialogBase.DialogAfterAction.WAIT_FOR_RESPONSE)
                .body(List.of(DialogBody.plainMessage(body)))
                .inputs(inputs)
                .build();

        ActionButton button = ActionButton.builder(plugin.messages().component(base + ".button", placeholders))
                .tooltip(plugin.messages().component(base + ".button-tooltip", placeholders))
                .width(160)
                // additions 传 null：这个形参是"待解析的 NBT"，非 null 时 Paper 会先解析成 Tag
                // 再断言必须是 compound（CustomClickActionImpl 的构造器），传字符串会被当成 SNBT
                // 解析出一个 string tag，直接抛 IllegalArgumentException。登录/注册由服务端会话决定，
                // 不需要附加数据；玩家填的输入值由客户端自己并进回传的 compound。
                .action(DialogAction.customClick(SUBMIT, null))
                .build();

        return Dialog.create(factory -> factory.empty()
                .base(dialogBase)
                .type(DialogType.multiAction(List.of(button)).columns(1).build()));
    }

    /** 用已经解析过的文本做占位符替换（错误行来自 messages 原文，这里只补占位符）。 */
    private String render(String raw, Map<String, String> placeholders) {
        String text = raw;
        for (Map.Entry<String, String> entry : placeholders.entrySet()) {
            text = text.replace("{" + entry.getKey() + "}", entry.getValue());
        }
        return text;
    }

    // ------------------------------------------------------------------
    // 工具
    // ------------------------------------------------------------------

    /** 断开并附上提示（配置阶段只能靠断开画面传达信息）。 */
    private void fail(PlayerConfigurationConnection connection, String key) {
        fail(connection, key, Map.of());
    }

    private void fail(PlayerConfigurationConnection connection, String key, Map<String, String> placeholders) {
        try {
            connection.disconnect(plugin.messages().component(key, placeholders));
        } catch (Throwable t) {
            plugin.getLogger().warning("[认证] 断开连接时出错: " + t);
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
            // 调度器已关闭（插件正在卸载）时退化为同步执行，保证会话不会悬挂
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
            return protocol >= DIALOG_MIN_PROTOCOL;
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
