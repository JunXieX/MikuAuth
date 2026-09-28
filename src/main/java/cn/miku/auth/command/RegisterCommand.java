package cn.miku.auth.command;

import cn.miku.auth.auth.AuthManager;
import cn.miku.auth.config.MikuMessages;
import com.velocitypowered.api.command.SimpleCommand;
import com.velocitypowered.api.proxy.Player;

import java.util.List;

/**
 * /register &lt;密码&gt; &lt;确认密码&gt; 命令：离线账号注册
 * （聊天栏与 Dialog 对话框共用入口）。
 *
 * <p>安全：suggest 永远返回空列表，防止密码被补全记录。
 */
public final class RegisterCommand implements SimpleCommand {

    private final AuthManager authManager;
    private final MikuMessages messages;

    public RegisterCommand(AuthManager authManager, MikuMessages messages) {
        this.authManager = authManager;
        this.messages = messages;
    }

    @Override
    public void execute(Invocation invocation) {
        if (!(invocation.source() instanceof Player player)) {
            invocation.source().sendMessage(messages.component("error.players-only"));
            return;
        }
        String[] args = invocation.arguments();
        String password = args.length > 0 ? args[0] : null;
        String confirm = args.length > 1 ? args[1] : null;
        authManager.handleRegisterCommand(player, password, confirm);
    }

    @Override
    public List<String> suggest(Invocation invocation) {
        return List.of(); // 敏感命令不提供参数补全
    }

    @Override
    public boolean hasPermission(Invocation invocation) {
        return invocation.source() instanceof Player;
    }
}
