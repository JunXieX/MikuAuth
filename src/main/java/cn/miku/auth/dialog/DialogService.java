package cn.miku.auth.dialog;

import cn.miku.auth.config.MikuConfig;
import cn.miku.auth.config.MikuMessages;
import cn.miku.auth.util.TextUtil;
import com.github.retrooper.packetevents.PacketEvents;
import com.github.retrooper.packetevents.protocol.dialog.CommonDialogData;
import com.github.retrooper.packetevents.protocol.dialog.Dialog;
import com.github.retrooper.packetevents.protocol.dialog.DialogAction;
import com.github.retrooper.packetevents.protocol.dialog.MultiActionDialog;
import com.github.retrooper.packetevents.protocol.dialog.action.Action;
import com.github.retrooper.packetevents.protocol.dialog.action.DialogTemplate;
import com.github.retrooper.packetevents.protocol.dialog.action.DynamicCustomAction;
import com.github.retrooper.packetevents.protocol.dialog.action.DynamicRunCommandAction;
import com.github.retrooper.packetevents.protocol.dialog.action.StaticAction;
import com.github.retrooper.packetevents.protocol.dialog.button.ActionButton;
import com.github.retrooper.packetevents.protocol.dialog.button.CommonButtonData;
import com.github.retrooper.packetevents.protocol.dialog.body.PlainMessage;
import com.github.retrooper.packetevents.protocol.dialog.body.PlainMessageDialogBody;
import com.github.retrooper.packetevents.protocol.dialog.input.Input;
import com.github.retrooper.packetevents.protocol.dialog.input.TextInputControl;
import com.github.retrooper.packetevents.protocol.nbt.NBTCompound;
import com.github.retrooper.packetevents.protocol.nbt.NBTString;
import com.github.retrooper.packetevents.protocol.player.ClientVersion;
import com.github.retrooper.packetevents.protocol.player.User;
import com.github.retrooper.packetevents.resources.ResourceLocation;
import com.github.retrooper.packetevents.wrapper.configuration.server.WrapperConfigServerShowDialog;
import com.github.retrooper.packetevents.wrapper.play.server.WrapperPlayServerShowDialog;
import com.velocitypowered.api.proxy.Player;
import net.kyori.adventure.text.Component;

import java.util.List;
import java.util.Map;
import org.slf4j.Logger;

/**
 * Dialog 对话框菜单服务：直接发送原版对话框数据包。
 *
 * <p>两个阶段各有一套包：
 * <ul>
 *   <li><b>play 阶段</b>（{@code WrapperPlayServerShowDialog}）：玩家已经进入认证服的世界，
 *       用于 {@code post} 登录模式；</li>
 *   <li><b>configuration 阶段</b>（{@code WrapperConfigServerShowDialog}）：玩家还在"加载地形"、
 *       尚未进入世界，用于 {@code pre} 登录模式 —— 认证完成前玩家看不到任何世界画面。</li>
 * </ul>
 *
 * <p><b>提交通道</b>（{@code dialog.submit-channel}）：
 * <ul>
 *   <li>{@code custom}（推荐）：按钮使用原版 {@code minecraft:dynamic/custom} 动作，客户端把输入值
 *       填进 NBT 后回发 {@code custom_click_action} 包。密码不经过命令系统，因此不会进入
 *       {@code .console_history}、玩家客户端历史或代理的命令日志；</li>
 *   <li>{@code command}：按钮执行 {@code /login $(password)}，由命令处理器接手。
 *       仅作为兼容兜底；<b>configuration 阶段没有命令通道，{@code pre} 模式强制走 custom</b>。</li>
 * </ul>
 *
 * <p><b>为什么 {@code pre} 强制 custom</b>：configuration 阶段客户端没有聊天栏、也没有命令输入框，
 * 唯一能回传数据的通道就是 {@code custom_click_action}。
 *
 * <p><b>可用性判定</b>（全部惰性执行，绝不在构造期缓存失败结果）：{@code dialog.enabled} 为 true、
 * packetevents 已就绪、客户端协议版本达标。任一不满足即返回失败原因，由调用方降级。
 */
public final class DialogService {

    /** play 阶段对话框的版本门槛：原版对话框自 1.21.6 起可用。 */
    private static final String MIN_VERSION_NAME = "1.21.6";
    /**
     * configuration 阶段对话框的版本门槛。
     *
     * <p>保守取 1.21.11：配置阶段的 {@code show_dialog} 是比 play 阶段更晚的能力，
     * 取偏高的门槛宁可让 1.21.6~1.21.9 的客户端回落到 {@code post} 模式（功能不受影响），
     * 也不能把不受支持的包发给它们 —— 状态不匹配的包会让客户端直接断开连接。
     */
    private static final String MIN_CONFIG_VERSION_NAME = "1.21.11";

    /** 提交动作的标识（客户端回发 {@code custom_click_action} 时原样带回）。 */
    public static final ResourceLocation SUBMIT_ID = new ResourceLocation("mikuauth:submit");
    /** 取消动作的标识：{@code pre} 模式下点击即断开。 */
    public static final ResourceLocation CANCEL_ID = new ResourceLocation("mikuauth:cancel");

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
     * 向玩家发送登录对话框（play 阶段，{@code post} 模式）。
     *
     * @param extraBodyLine 附加在正文末尾的文本（如错误提示）；null = 无
     * @return null = 发送成功；否则返回失败原因（用于日志与降级提示）
     */
    public String showLogin(Player player, String extraBodyLine) {
        // 先确认 PacketEvents 可用再构建对话框：buildDialog 会直接引用其协议类，
        // 未安装时构建即抛类链接错误（调用方虽会兜底，但这里应尽早给出明确原因）
        if (!checkPacketEvents()) {
            return "packetevents 插件未安装或未就绪";
        }
        return sendPlay(player, buildDialog(player, "dialog.login", false, extraBodyLine, false));
    }

    /** 向玩家发送注册对话框（play 阶段，密码 + 确认密码两个输入框）。 */
    public String showRegister(Player player, String extraBodyLine) {
        if (!checkPacketEvents()) {
            return "packetevents 插件未安装或未就绪";
        }
        return sendPlay(player, buildDialog(player, "dialog.register", true, extraBodyLine, false));
    }

    /**
     * 向玩家发送 configuration 阶段的登录/注册对话框（{@code pre} 模式）。
     *
     * <p>必须在 {@code PlayerConfigurationEvent} 的处理链里调用：那一刻注册表数据已经下发，
     * 客户端可以正常渲染对话框，而世界还没有开始加载。
     *
     * @return null = 发送成功；否则返回失败原因（调用方据此回落到 play 阶段流程）
     */
    public String showInConfiguration(Player player, boolean register, String extraBodyLine) {
        if (!configPhaseSupportedByRuntime()) {
            return "packetevents 版本不支持 configuration 阶段对话框";
        }
        if (!checkPacketEvents()) {
            return "packetevents 插件未安装或未就绪";
        }
        if (!supportsConfigPhase(player)) {
            return "客户端版本低于 " + MIN_CONFIG_VERSION_NAME + "（或协议版本未知）";
        }
        User user = packetEventsApi.getPlayerManager().getUser(player);
        if (user == null) {
            return "PacketEvents 未跟踪该玩家连接";
        }
        Dialog dialog = buildDialog(player, register ? "dialog.register" : "dialog.login",
                register, extraBodyLine, true);
        try {
            packetEventsApi.getPlayerManager().sendPacket(player, new WrapperConfigServerShowDialog(dialog));
            return null;
        } catch (Throwable t) {
            return "发送异常: " + t.getClass().getSimpleName() + (t.getMessage() != null ? " " + t.getMessage() : "");
        }
    }

    /**
     * 运行期是否具备 configuration 阶段对话框的类（包 {@code packetevents-api} 版本是否够新）。
     *
     * <p>用 {@code Class.forName} 探测而不是直接引用：服主装的 {@code packetevents-velocity}
     * 可能比编译期依赖旧，缺类时会抛 {@link NoClassDefFoundError}（Error 而非 Exception），
     * 必须在这里就拦下并降级。
     */
    public static boolean configPhaseSupportedByRuntime() {
        try {
            Class.forName("com.github.retrooper.packetevents.wrapper.configuration.server.WrapperConfigServerShowDialog");
            Class.forName("com.github.retrooper.packetevents.wrapper.configuration.client.WrapperConfigClientCustomClickAction");
            return true;
        } catch (Throwable t) {
            return false;
        }
    }

    /** 该玩家的客户端能否接收 configuration 阶段的对话框。 */
    public boolean supportsConfigPhase(Player player) {
        if (!checkPacketEvents()) {
            return false;
        }
        User user = packetEventsApi.getPlayerManager().getUser(player);
        if (user == null) {
            return false;
        }
        ClientVersion version = user.getClientVersion();
        // 协议未知（PacketEvents 尚未支持的新版本）：绝不能"试着发"——
        // 用错误的协议号编码 dialog 包会让客户端收到不匹配的数据并断开连接
        if (version == ClientVersion.UNKNOWN) {
            return false;
        }
        return version.isNewerThanOrEquals(ClientVersion.V_1_21_11);
    }

    /** 当前提交通道是否为 custom（配置阶段强制 custom）。 */
    public boolean usesCustomSubmit(boolean configPhase) {
        return configPhase || !"command".equals(config.submitChannel());
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
     * 构建对话框（双按钮：提交 + 关闭/取消）。
     *
     * <p><b>关闭检测设计</b>：客户端按 Esc 关闭对话框不产生任何网络包，
     * 服务器无法感知。因此这里 {@code canCloseWithEscape = false}（禁止 Esc），并提供一个按钮：
     * <ul>
     *   <li>play 阶段：「返回聊天栏」→ 执行 {@code /mikuauth-close}，服务器由此得知对话框已关闭；</li>
     *   <li>configuration 阶段：「取消」→ 回发 {@code custom_click_action}，服务器据此断开连接
     *       （该阶段没有聊天栏可以退回）。</li>
     * </ul>
     *
     * @param base        文本键前缀（dialog.login / dialog.register）
     * @param withConfirm 是否带"确认密码"输入框（注册用）
     * @param extraLine   附加正文行（如错误提示）；null = 无
     * @param configPhase 是否为 configuration 阶段（决定按钮语义）
     */
    private Dialog buildDialog(Player player, String base, boolean withConfirm,
                               String extraLine, boolean configPhase) {
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
                submitAction(withConfirm, configPhase));

        // 配置阶段没有聊天栏：次要按钮 = "退出登录"（断开）。它是玩家唯一的退路，
        // 因此由 login.pre.show-cancel-button 控制与否都要显式说明（关掉后只能等超时）。
        ActionButton secondary = configPhase
                ? (config.preAuthShowCancelButton() ? configCancelButton(base, placeholders) : null)
                : playCloseButton(base, placeholders);

        return new MultiActionDialog(common, List.of(submitButton), secondary, 1);
    }

    /**
     * 提交动作：custom（默认，密码不进命令系统）或 command（兼容兜底）。
     *
     * <p>custom 的 payload 是一份最小 NBT：值写成 {@code $(key)} 形式，由客户端在发送前
     * 替换为输入框内容。服务端只读替换后的结果，因此不做任何模板解析。
     */
    private Action submitAction(boolean withConfirm, boolean configPhase) {
        if (usesCustomSubmit(configPhase)) {
            NBTCompound payload = new NBTCompound();
            payload.setTag("password", new NBTString("$(password)"));
            if (withConfirm) {
                payload.setTag("confirm", new NBTString("$(confirm)"));
            }
            return new DynamicCustomAction(SUBMIT_ID, payload);
        }
        String command = withConfirm
                ? "/register $(password) $(confirm)"
                : "/login $(password)";
        return new DynamicRunCommandAction(new DialogTemplate(command));
    }

    /** play 阶段的次要按钮：返回聊天栏（执行内部命令，服务器可感知）。 */
    private ActionButton playCloseButton(String base, Map<String, String> placeholders) {
        return new ActionButton(
                new CommonButtonData(
                        messages.component(base + ".close-button", placeholders),
                        messages.component(base + ".close-button-tooltip", placeholders),
                        160),
                new StaticAction(com.github.retrooper.packetevents.protocol.chat.clickevent.ClickEvent
                        .fromAdventure(net.kyori.adventure.text.event.ClickEvent.runCommand("/mikuauth-close"))));
    }

    /**
     * configuration 阶段的次要按钮：取消本次登录（断开连接）。
     *
     * <p>该阶段没有聊天栏，无法"返回聊天栏"；不放这个按钮的话，玩家在网络异常时
     * 只能干等到超时被踢。可用 {@code login.pre.show-cancel-button} 关掉。
     */
    private ActionButton configCancelButton(String base, Map<String, String> placeholders) {
        return new ActionButton(
                new CommonButtonData(
                        messages.component(base + ".cancel-button", placeholders),
                        messages.component(base + ".cancel-button-tooltip", placeholders),
                        160),
                new DynamicCustomAction(CANCEL_ID, null));
    }

    // ---------------------------------------------------------------------
    // 发送
    // ---------------------------------------------------------------------

    /**
     * 发送 play 阶段的数据包。
     *
     * @return null = 成功；非 null = 失败原因
     */
    private String sendPlay(Player player, Dialog dialog) {
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
        if (version == ClientVersion.UNKNOWN) {
            return "PacketEvents 尚未识别该客户端协议版本（可能为过新的 MC 版本），已降级为聊天栏提示";
        }
        if (!version.isNewerThanOrEquals(ClientVersion.V_1_21_6)) {
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
