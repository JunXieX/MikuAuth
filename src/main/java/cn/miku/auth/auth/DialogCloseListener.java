package cn.miku.auth.auth;

import com.github.retrooper.packetevents.PacketEvents;
import com.github.retrooper.packetevents.event.PacketListenerAbstract;
import com.github.retrooper.packetevents.event.PacketListenerPriority;
import com.github.retrooper.packetevents.event.PacketReceiveEvent;
import com.github.retrooper.packetevents.protocol.packettype.PacketType;
import com.github.retrooper.packetevents.protocol.packettype.PacketTypeCommon;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;

import java.util.Set;

/**
 * PacketEvents 包监听：对话框关闭的兜底检测。
 *
 * <p>正常流程中对话框的关闭由 {@code /mikuauth-close} 命令感知（Esc 已禁用，
 * 退出必经按钮命令）。本监听器仅在异常场景兜底：若对话框打开期间仍收到
 * 聊天/命令包（说明客户端根本没显示对话框，如第三方客户端或渲染异常），
 * 解除静默并给出聊天栏提示，避免玩家停留在无提示状态。
 *
 * <p>未认证玩家的移动/方块/背包拦截由认证服（limbo）物理隔离，代理层不做
 * 包级操作拦截——插件要求必须配置 auth-server，玩家在认证完成前
 * 根本不会进入真实服务器。
 */
public final class DialogCloseListener extends PacketListenerAbstract {

    /** 对话框打开时不应出现的客户端输入包（出现即说明对话框未生效）。 */
    private static final Set<PacketTypeCommon> CHAT_PACKETS = Set.of(
            PacketType.Play.Client.CHAT_MESSAGE,
            PacketType.Play.Client.CHAT_COMMAND,
            PacketType.Play.Client.CHAT_COMMAND_UNSIGNED);

    private final ProxyServer server;
    private final AuthManager authManager;

    public DialogCloseListener(ProxyServer server, AuthManager authManager) {
        super(PacketListenerPriority.LOW);
        this.server = server;
        this.authManager = authManager;
    }

    @Override
    public void onPacketReceive(PacketReceiveEvent event) {
        PacketTypeCommon type = event.getPacketType();
        if (!CHAT_PACKETS.contains(type)) {
            return;
        }
        Player player = server.getPlayer(event.getUser().getUUID()).orElse(null);
        if (player == null) {
            return;
        }
        authManager.handleClientActivity(player);
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
        api.getEventManager().registerListener(new DialogCloseListener(server, authManager));
        return true;
    }
}
