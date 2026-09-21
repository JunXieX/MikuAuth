package cn.miku.auth.dialog;

import cn.miku.auth.config.MikuConfig;
import cn.miku.auth.config.MikuMessages;
import cn.miku.auth.util.TextUtil;
import com.github.retrooper.packetevents.PacketEvents;
import com.github.retrooper.packetevents.protocol.dialog.CommonDialogData;
import com.github.retrooper.packetevents.protocol.dialog.DialogAction;
import com.github.retrooper.packetevents.protocol.dialog.Dialog;
import com.github.retrooper.packetevents.protocol.dialog.MultiActionDialog;
import com.github.retrooper.packetevents.protocol.dialog.action.StaticAction;
import com.github.retrooper.packetevents.protocol.dialog.button.ActionButton;
import com.github.retrooper.packetevents.protocol.dialog.button.CommonButtonData;
import com.github.retrooper.packetevents.protocol.dialog.action.DialogTemplate;
import com.github.retrooper.packetevents.protocol.dialog.action.DynamicRunCommandAction;
import com.github.retrooper.packetevents.protocol.dialog.body.PlainMessage;
import com.github.retrooper.packetevents.protocol.dialog.body.PlainMessageDialogBody;
import com.github.retrooper.packetevents.protocol.dialog.input.Input;
import com.github.retrooper.packetevents.protocol.dialog.input.TextInputControl;
import com.github.retrooper.packetevents.protocol.player.User;
import com.github.retrooper.packetevents.wrapper.play.server.WrapperPlayServerShowDialog;
import com.velocitypowered.api.proxy.Player;
import net.kyori.adventure.text.Component;

import java.util.List;
import java.util.Map;
import org.slf4j.Logger;

/**
 * Dialog 对话框菜单服务：直接发送原版 1.21.6+ 的 show_dialog 数据包。
 *
 * <p>Velocity 没有任何对话框 API（Adventure 的 DialogLike 在代理端是空操作），
 * 因此使用 PacketEvents 构建协议包。提交按钮使用原版
 * {@code minecraft:dynamic/run_command} 动作：客户端将 {@code $(key)}
 * 替换为输入值后执行代理命令，登录/注册逻辑直接复用命令处理器，
 * 无需额外回包协议。
 *
 * <p>可用性判定（全部惰性执行，绝不在构造期缓存）：
 * <ul>
 *   <li>packetevents-velocity 插件已安装且 API 就绪；</li>
 *   <li>玩家客户端版本 ≥ 1.21.6。</li>
 * </ul>
 * 任一条件不满足即降级为聊天栏 + Title + BossBar 提示。
 *
 * <p><b>本类只"发送"对话框，不"关闭"它</b>：对话框的两个按钮都走
 * {@link DialogAction#CLOSE}，客户端在按钮动作执行后自行关闭界面；"返回聊天栏"
 * 按钮则通过 {@code /mikuauth-close} 让服务器感知到关闭。因此服务端没有
 * "主动清对话框"的剩余场景。
 *
 * <p>这里刻意<b>不提供</b>一个未被调用的 {@code clear()}：发 ClearDialog 包前
 * 必须确认客户端支持 Dialog 协议，否则 PacketEvents 尚未识别的新版本（如 26.x，
 * {@code getClientVersion()} 返回 UNKNOWN）会被编码成协议不匹配的包，
 * 客户端收到后<b>直接断开连接</b>（实测踩坑）。留着没有调用点的死方法，
 * 只会诱导将来在错误的时机调用它。
 */
public final class DialogService {

    /** 版本门槛：原版对话框自 1.21.6 起可用。 */
    private static final String MIN_VERSION_NAME = "1.21.6";

    private final MikuConfig config;
    private final MikuMessages messages;
    private final Logger logger;
    /** PacketEvents API 就绪标志（每次发送前惰性校验，早期 null 不缓存）。 */
    private volatile com.github.retrooper.packetevents.PacketEventsAPI<?> packetEventsApi;
    private volatile boolean packetEventsChecked;

    public DialogService(MikuConfig config, MikuMessages messages, Logger logger) {
        this.config = config;
        this.messages = messages;
        this.logger = logger;
    }

    // ---------------------------------------------------------------------
    // 对外动作
    // ---------------------------------------------------------------------

    /**
     * 向玩家发送登录对话框。
     *
     * @param extraBodyLine 附加在正文末尾的文本（如错误提示）；null = 无
     * @return null = 发送成功；否则返回失败原因（用于日志与降级提示）
     */
    public String showLogin(Player player, String extraBodyLine) {
        return send(player, buildDialog(player, "dialog.login",
                "/login $(password)", extraBodyLine, false));
    }

    /**
     * 向玩家发送注册对话框（密码 + 确认密码两个输入框）。
     *
     * @param extraBodyLine 附加在正文末尾的文本（如错误提示）；null = 无
     */
    public String showRegister(Player player, String extraBodyLine) {
        return send(player, buildDialog(player, "dialog.register",
                "/register $(password) $(confirm)", extraBodyLine, true));
    }

    /**
     * 配置的认证时限文本（login.timeout-seconds）；0（不限时）显示 ∞。
     */
    private String secondsText() {
        int timeout = config.authTimeoutSeconds();
        return timeout > 0 ? String.valueOf(timeout) : "∞";
    }

    // ---------------------------------------------------------------------
    // 构建
    // ---------------------------------------------------------------------

    /**
     * 构建对话框（双按钮：提交 + 返回聊天栏）。
     *
     * <p><b>关闭检测设计</b>：客户端按 Esc 关闭对话框不产生任何网络包，
     * 服务器无法感知。因此这里 {@code canCloseWithEscape = false}（禁止 Esc），
     * 并提供"返回聊天栏"按钮——点击时执行 {@code /mikuauth-close} 命令，
     * 服务器由此可靠地得知对话框已关闭，从而正确恢复 Title/BossBar/聊天提示。
     * 提交按钮则通过 {@code dynamic/run_command} 执行登录/注册命令，同样有信号。
     * 对话框的所有退出路径都在服务器可感知范围内。
     *
     * <p>文本键统一由 {@code base} 派生（{@code <base>.title} / {@code .body} /
     * {@code .input-label} / {@code .button} / {@code .button-tooltip} /
     * {@code .close-button} / {@code .close-button-tooltip}，注册另含
     * {@code .confirm-label}），避免用 {@code String.replace} 拼接键名。
     *
     * @param base        文本键前缀（dialog.login / dialog.register）
     * @param withConfirm 是否带"确认密码"输入框（注册用）
     * @param extraLine   附加正文行（如错误提示）；null = 无
     */
    private Dialog buildDialog(Player player, String base, String commandTemplate,
                               String extraLine, boolean withConfirm) {
        // {seconds} = 配置的认证时限（login.timeout-seconds），固定值而非倒计时
        Map<String, String> placeholders = Map.of(
                "player", player.getUsername(),
                "seconds", secondsText());
        Component title = messages.component(base + ".title", placeholders);
        Component body = messages.component(base + ".body", placeholders);
        if (extraLine != null && !extraLine.isEmpty()) {
            body = Component.text().append(body)
                    .append(Component.newline())
                    .append(TextUtil.render(extraLine))
                    .build();
        }
        Component inputLabel = messages.component(base + ".input-label", placeholders);
        // 输入框上限跟随 registration.max-password-length，避免"允许输入 64 位但配置只接受 32 位"
        int maxLength = config.maxPasswordLength();

        List<Input> inputs = withConfirm
                ? List.of(
                        new Input("password", new TextInputControl(320, inputLabel, true, "", maxLength, null)),
                        new Input("confirm", new TextInputControl(320,
                                messages.component(base + ".confirm-label", placeholders),
                                true, "", maxLength, null)))
                : List.of(new Input("password", new TextInputControl(320, inputLabel, true, "", maxLength, null)));

        CommonDialogData common = new CommonDialogData(
                title,
                title,                                    // 外部标题（对话框列表/致谢界面显示）
                false,                                    // 禁止 Esc 关闭：保证退出路径服务器可感知
                false,                                    // 不暂停游戏（无需响应式等待）
                DialogAction.CLOSE,                       // 点击按钮后关闭对话框
                List.of(new PlainMessageDialogBody(new PlainMessage(body, 320))),
                inputs);

        ActionButton submitButton = new ActionButton(
                new CommonButtonData(
                        messages.component(base + ".button", placeholders),
                        messages.component(base + ".button-tooltip", placeholders),
                        160),
                new DynamicRunCommandAction(new DialogTemplate(commandTemplate)));

        ActionButton closeButton = new ActionButton(
                new CommonButtonData(
                        messages.component(base + ".close-button", placeholders),
                        messages.component(base + ".close-button-tooltip", placeholders),
                        160),
                new StaticAction(com.github.retrooper.packetevents.protocol.chat.clickevent.ClickEvent
                        .fromAdventure(net.kyori.adventure.text.event.ClickEvent.runCommand("/mikuauth-close"))));

        return new MultiActionDialog(common, List.of(submitButton), closeButton, 1);
    }

    // ---------------------------------------------------------------------
    // 发送
    // ---------------------------------------------------------------------

    /**
     * 实际发送数据包。
     *
     * @return null = 成功；非 null = 失败原因
     */
    private String send(Player player, Dialog dialog) {
        if (!checkPacketEvents()) {
            return "packetevents 插件未安装或未就绪";
        }
        var api = packetEventsApi;
        User user = api.getPlayerManager().getUser(player);
        if (user == null) {
            return "PacketEvents 未跟踪该玩家连接";
        }
        var version = user.getClientVersion();
        // 协议未知（PacketEvents 尚未支持的新版本，如 26.x）：绝不能"试着发"——
        // 用错误的协议号编码 dialog 包会让客户端收到不匹配的数据并断开连接。
        // 这里直接降级为聊天栏提示，等 PacketEvents 支持该版本后自动恢复对话框。
        if (version == com.github.retrooper.packetevents.protocol.player.ClientVersion.UNKNOWN) {
            return "PacketEvents 尚未识别该客户端协议版本（可能为过新的 MC 版本），已降级为聊天栏提示";
        }
        if (!version.isNewerThanOrEquals(
                com.github.retrooper.packetevents.protocol.player.ClientVersion.V_1_21_6)) {
            return "客户端版本低于 " + MIN_VERSION_NAME;
        }
        try {
            api.getPlayerManager().sendPacket(player, new WrapperPlayServerShowDialog(dialog));
            return null;
        } catch (Throwable t) {
            return "发送异常: " + t.getClass().getSimpleName() + (t.getMessage() != null ? " " + t.getMessage() : "");
        }
    }

    /** 惰性校验 PacketEvents API 可用性。 */
    private boolean checkPacketEvents() {
        if (packetEventsChecked) {
            return packetEventsApi != null;
        }
        try {
            Class.forName("com.github.retrooper.packetevents.PacketEvents");
            com.github.retrooper.packetevents.PacketEventsAPI<?> api = PacketEvents.getAPI();
            packetEventsApi = api != null && api.isLoaded() ? api : null;
        } catch (Throwable t) {
            packetEventsApi = null;
        }
        packetEventsChecked = packetEventsApi != null;
        if (packetEventsApi == null && logger != null) {
            logger.debug("[对话框] PacketEvents 不可用，Dialog 菜单已降级");
        }
        return packetEventsApi != null;
    }
}
