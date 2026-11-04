package cn.miku.auth.auth;

import cn.miku.auth.dialog.DialogService;
import com.github.retrooper.packetevents.PacketEvents;
import com.github.retrooper.packetevents.event.PacketListenerAbstract;
import com.github.retrooper.packetevents.event.PacketListenerPriority;
import com.github.retrooper.packetevents.event.PacketReceiveEvent;
import com.github.retrooper.packetevents.protocol.nbt.NBT;
import com.github.retrooper.packetevents.protocol.nbt.NBTCompound;
import com.github.retrooper.packetevents.protocol.packettype.PacketType;
import com.github.retrooper.packetevents.protocol.packettype.PacketTypeCommon;
import com.github.retrooper.packetevents.resources.ResourceLocation;
import com.github.retrooper.packetevents.wrapper.configuration.client.WrapperConfigClientCustomClickAction;
import com.github.retrooper.packetevents.wrapper.play.client.WrapperPlayClientCustomClickAction;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;

import java.util.Set;

/**
 * PacketEvents 包监听：对话框的提交/取消信号与关闭兜底检测。
 *
 * <p>两类职责：
 * <ol>
 *   <li><b>提交通道</b>：对话框按钮使用 {@code dynamic/custom} 动作时，客户端回发
 *       {@code custom_click_action}（play 与 configuration 两态各有一个包）。这里把输入值
 *       直接交给认证状态机 —— 密码不经过命令系统，因此不会进入命令历史与代理日志；</li>
 *   <li><b>关闭兜底</b>：正常流程下对话框的关闭由按钮信号感知（Esc 已禁用）。若对话框打开期间
 *       仍收到聊天/命令包，说明客户端根本没显示对话框（第三方客户端或渲染异常），
 *       这里解除静默并给出聊天栏提示，避免玩家停留在无提示状态。</li>
 * </ol>
 *
 * <p>未认证玩家的移动/方块/背包拦截由认证服（limbo）物理隔离，代理层不做包级拦截 ——
 * 插件要求必须配置 auth-server，玩家在认证完成前根本不会进入真实服务器。
 */
public final class DialogPacketListener extends PacketListenerAbstract {

    /** 对话框打开时不应出现的客户端输入包（出现即说明对话框未生效）。 */
    private static final Set<PacketTypeCommon> CHAT_PACKETS = Set.of(
            PacketType.Play.Client.CHAT_MESSAGE,
            PacketType.Play.Client.CHAT_COMMAND,
            PacketType.Play.Client.CHAT_COMMAND_UNSIGNED);

    private final ProxyServer server;
    private final AuthManager authManager;

    public DialogPacketListener(ProxyServer server, AuthManager authManager) {
        super(PacketListenerPriority.LOW);
        this.server = server;
        this.authManager = authManager;
    }

    @Override
    public void onPacketReceive(PacketReceiveEvent event) {
        PacketTypeCommon type = event.getPacketType();
        if (CHAT_PACKETS.contains(type)) {
            Player player = playerOf(event);
            if (player != null) {
                authManager.handleClientActivity(player);
            }
            return;
        }
        if (type == PacketType.Play.Client.CUSTOM_CLICK_ACTION) {
            WrapperPlayClientCustomClickAction wrapper = new WrapperPlayClientCustomClickAction(event);
            dispatch(playerOf(event), wrapper.getId(), wrapper.getPayload(), false);
        } else if (isConfigCustomClick(type)) {
            WrapperConfigClientCustomClickAction wrapper = new WrapperConfigClientCustomClickAction(event);
            dispatch(playerOf(event), wrapper.getId(), wrapper.getPayload(), true);
        }
    }

    /**
     * 是否为 configuration 阶段的 custom_click_action。
     *
     * <p>包在 try 内：老版本 packetevents 没有这个包类型，直接引用会抛
     * {@link NoClassDefFoundError}（Error 而非 Exception），不能让它在 Netty 线程上冒泡。
     */
    private static boolean isConfigCustomClick(PacketTypeCommon type) {
        try {
            return type == PacketType.Configuration.Client.CUSTOM_CLICK_ACTION;
        } catch (Throwable t) {
            return false;
        }
    }

    /** 分发一次 custom 动作：提交（mikuauth:submit）或取消（mikuauth:cancel）。 */
    private void dispatch(Player player, ResourceLocation id, NBT payload, boolean configPhase) {
        if (player == null || id == null) {
            return;
        }
        String idText = id.toString();
        if (DialogService.SUBMIT_ID.toString().equals(idText)) {
            authManager.handleDialogSubmit(player,
                    stringOf(payload, "password"), stringOf(payload, "confirm"), configPhase);
        } else if (DialogService.CANCEL_ID.toString().equals(idText)) {
            authManager.handleDialogCancel(player, configPhase);
        }
    }

    /** 从 payload 中取一个字符串字段；缺失或类型不符一律返回空串（按"未填写"处理）。 */
    private static String stringOf(NBT payload, String key) {
        if (payload instanceof NBTCompound compound) {
            String value = compound.getStringTagValueOrNull(key);
            return value == null ? "" : value;
        }
        return "";
    }

    private Player playerOf(PacketReceiveEvent event) {
        if (event.getUser() == null) {
            return null;
        }
        return server.getPlayer(event.getUser().getUUID()).orElse(null);
    }

    /**
     * 注册监听器；PacketEvents 尚未就绪时返回 false（调用方可延迟重试）。
     * 类链接失败必须由调用方 catch（跨插件可选依赖的异常发生在调用处）。
     */
    public static boolean tryRegister(ProxyServer server, AuthManager authManager) {
        com.github.retrooper.packetevents.PacketEventsAPI<?> api = PacketEvents.getAPI();
        if (api == null || !api.isLoaded()) {
            return false;
        }
        api.getEventManager().registerListener(new DialogPacketListener(server, authManager));
        return true;
    }
}
