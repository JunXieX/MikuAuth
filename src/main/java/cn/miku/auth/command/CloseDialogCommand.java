package cn.miku.auth.command;

import cn.miku.auth.auth.AuthManager;
import com.velocitypowered.api.command.SimpleCommand;
import com.velocitypowered.api.proxy.Player;

import java.util.List;

/**
 * /mikuauth-close —— 对话框"返回聊天栏"按钮的内部命令。
 *
 * <p>Dialog 禁用了 Esc 关闭，玩家点击"返回聊天栏"按钮时客户端执行本命令，
 * 服务器由此可靠得知对话框已关闭，解除静默并给出聊天栏用法提示。
 * 该命令对手动执行的重复调用是幂等的（对话框未打开时直接忽略）。
 */
public final class CloseDialogCommand implements SimpleCommand {

    private final AuthManager authManager;

    public CloseDialogCommand(AuthManager authManager) {
        this.authManager = authManager;
    }

    @Override
    public void execute(Invocation invocation) {
        if (invocation.source() instanceof Player player) {
            authManager.handleClientActivity(player);
        }
    }

    @Override
    public List<String> suggest(Invocation invocation) {
        return List.of();
    }

    @Override
    public boolean hasPermission(Invocation invocation) {
        return invocation.source() instanceof Player;
    }
}
