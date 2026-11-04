package cn.miku.auth.paper;

import io.papermc.paper.connection.PlayerConfigurationConnection;
import io.papermc.paper.dialog.Dialog;
import io.papermc.paper.event.connection.configuration.AsyncPlayerConnectionConfigureEvent;
import io.papermc.paper.event.player.PlayerCustomClickEvent;
import io.papermc.paper.registry.data.dialog.DialogBase;
import io.papermc.paper.registry.data.dialog.ActionButton;
import io.papermc.paper.registry.data.dialog.action.DialogAction;
import io.papermc.paper.registry.data.dialog.body.DialogBody;
import io.papermc.paper.registry.data.dialog.input.DialogInput;
import io.papermc.paper.registry.data.dialog.type.DialogType;
import net.kyori.adventure.key.Key;
import net.kyori.adventure.nbt.api.BinaryTagHolder;
import net.kyori.adventure.text.Component;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * 进服前认证闸门：只实现「Pre」模式。
 *
 * <p><b>时序</b>：{@link AsyncPlayerConnectionConfigureEvent} 在配置阶段完成之后、玩家进入世界之前触发，
 * 且服务端会等监听器执行完才继续这条连接。因此这里可以：
 * <ol>
 *   <li>用 {@link PlayerConfigurationConnection#getAudience()} 把原生对话框发给玩家；</li>
 *   <li>阻塞等待玩家提交（超时由配置决定）；</li>
 *   <li>认证通过就直接返回 —— 连接继续，玩家进入世界；失败则重发对话框或断开。</li>
 * </ol>
 *
 * <p><b>为什么可以阻塞</b>：该事件本身跑在异步线程上，且它就是"配置阶段的最后一道工序"；
 * 阻塞的是这名玩家自己的连接线程，不影响主线程 tick。超时必须有界，否则连接会永久悬挂。
 *
 * <p><b>只支持一种模式</b>：不做"进服后冻结再登录"的 Post 模式 —— 服务端一旦让玩家进入世界，
 * 就无法在不接管实体的情况下保证他看不到地形。
 */
public final class PreJoinGate implements Listener {

    /** 提交动作的标识（客户端点击后由 {@link PlayerCustomClickEvent} 带回）。 */
    static final Key SUBMIT = Key.key("mikuauth", "submit");

    private final MikuAuthPlugin plugin;
    /** 跨连接的失败计数与临时封禁（断线重连绕不过去）。 */
    private final Throttle throttle;
    /** 正在配置阶段等待认证的连接；键为玩家 UUID。 */
    private final ConcurrentHashMap<UUID, Session> sessions = new ConcurrentHashMap<>();

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
        volatile int tries;
        volatile boolean finished;

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
    }

    // ------------------------------------------------------------------
    // 闸门
    // ------------------------------------------------------------------

    @EventHandler(priority = EventPriority.NORMAL)
    public void onConfigure(AsyncPlayerConnectionConfigureEvent event) {
        PlayerConfigurationConnection connection = event.getConnection();
        UUID id = connection.getProfile().getId();
        String name = connection.getProfile().getName();
        if (name == null || name.isEmpty()) {
            connection.disconnect(plugin.messages().component("kick.internal-error"));
            return;
        }
        // 被封禁的 IP/账号在弹框之前就拒绝，避免白送一次哈希计算
        var lock = throttle.check(addressOf(connection), name);
        if (lock != null) {
            connection.disconnect(plugin.messages().component("kick.locked",
                    java.util.Map.of("minutes", String.valueOf(lock.minutes()))));
            return;
        }
        Store.Account account = plugin.store().find(name);
        String textKey = account != null && account.hasPassword() ? "login" : "register";
        Session session = new Session(id, name, addressOf(connection), connection, textKey);
        sessions.put(id, session);
        try {
            showDialog(session, null);
            // 阻塞到提交成功 / 超次断开 / 超时；服务端在此期间不会让玩家进入世界
            session.done.get(plugin.config().timeoutSeconds(), TimeUnit.SECONDS);
        } catch (TimeoutException timeout) {
            if (!session.finished) {
                session.finished = true;
                connection.disconnect(plugin.messages().component("kick.timeout"));
            }
        } catch (Exception e) {
            plugin.getLogger().warning("[认证] " + name + " 的配置阶段认证异常: " + e);
            if (!session.finished) {
                session.finished = true;
                connection.disconnect(plugin.messages().component("kick.internal-error"));
            }
        } finally {
            sessions.remove(id);
        }
    }

    /** 对话框提交（自定义点击）。事件可能来自配置阶段，也可能来自游戏内，这里只处理后者的前者。 */
    @EventHandler(priority = EventPriority.NORMAL)
    public void onCustomClick(PlayerCustomClickEvent event) {
        if (!SUBMIT.equals(event.getIdentifier())) {
            return;
        }
        if (!(event.getCommonConnection() instanceof PlayerConfigurationConnection connection)) {
            return;
        }
        Session session = sessions.get(connection.getProfile().getId());
        if (session == null || session.finished) {
            return;
        }
        var view = event.getDialogResponseView();
        String password = view == null ? null : view.getText("password");
        String confirm = view == null ? null : view.getText("confirm");
        if (session.registering()) {
            submitRegister(session, password, confirm);
        } else {
            submitLogin(session, password);
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
        var lock = throttle.recordFailure(session.ip, session.name);
        plugin.store().audit(session.name, session.id, session.ip, "LOGIN_FAIL",
                "密码错误（本次连接第 " + session.tries + " 次）"
                        + (lock != null ? "，已触发临时封禁" : ""));
        if (lock != null) {
            session.finished = true;
            session.connection.disconnect(plugin.messages().component("kick.locked",
                    java.util.Map.of("minutes", String.valueOf(lock.minutes()))));
            session.done.complete(null);
            return;
        }
        if (session.tries >= plugin.config().maxTries()) {
            session.finished = true;
            session.connection.disconnect(plugin.messages().component("kick.too-many-tries"));
            session.done.complete(null);
            return;
        }
        retry(session, plugin.messages().raw("error.password-wrong"), Map.of());
    }

    /** 认证通过：记审计 + 放行（返回后连接继续，玩家进入世界）。 */
    private void succeed(Session session, String messageKey, String action, String detail) {
        session.finished = true;
        throttle.reset(session.name);
        plugin.store().finishLogin(session.name, session.ip);
        plugin.store().audit(session.name, session.id, session.ip, action, detail);
        session.connection.getAudience().sendMessage(
                plugin.messages().component(messageKey + ".chat", Map.of("player", session.name)));
        session.done.complete(null);
    }

    /** 失败：把错误拼进正文后重发同一个对话框。 */
    private void retry(Session session, String errorRaw, Map<String, String> placeholders) {
        showDialog(session, render(errorRaw, placeholders));
    }

    private void showDialog(Session session, String errorLine) {
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
        DialogBase.Builder dialogBase = DialogBase.builder(plugin.messages().component(base + ".title", placeholders))
                .canCloseWithEscape(config.allowCloseWithEscape())
                .body(List.of(DialogBody.plainMessage(body)));
        // 显式声明为 List<DialogInput>：inputs(...) 的形参是通配符列表，
        // 直接传 List.of(...) 会让编译器在推断元素类型时与通配符边界冲突
        List<DialogInput> inputs = new java.util.ArrayList<>(register ? 2 : 1);
        // DialogInput.text(...) 返回的是 Builder，必须 build() 才是 DialogInput
        inputs.add(DialogInput.text("password",
                plugin.messages().component(base + ".input-label", placeholders)).build());
        if (register) {
            inputs.add(DialogInput.text("confirm",
                    plugin.messages().component(base + ".confirm-label", placeholders)).build());
        }
        dialogBase.inputs(inputs);

        ActionButton button = ActionButton.builder(plugin.messages().component(base + ".button", placeholders))
                .tooltip(plugin.messages().component(base + ".button-tooltip", placeholders))
                .width(160)
                .action(DialogAction.customClick(SUBMIT, BinaryTagHolder.binaryTagHolder(session.textKey)))
                .build();

        Dialog dialog = Dialog.create(factory -> factory.empty()
                .base(dialogBase.build())
                .type(DialogType.multiAction(List.of(button)).build()));
        session.connection.getAudience().showDialog(dialog);
    }

    /** 用已经解析过的文本做占位符替换（错误行来自 messages 原文，这里只补占位符）。 */
    private String render(String raw, Map<String, String> placeholders) {
        String text = raw;
        for (Map.Entry<String, String> entry : placeholders.entrySet()) {
            text = text.replace("{" + entry.getKey() + "}", entry.getValue());
        }
        return text;
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
