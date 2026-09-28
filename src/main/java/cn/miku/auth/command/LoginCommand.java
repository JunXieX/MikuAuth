package cn.miku.auth.command;

import cn.miku.auth.auth.AuthManager;
import cn.miku.auth.config.MikuMessages;
import com.velocitypowered.api.command.SimpleCommand;
import com.velocitypowered.api.proxy.Player;

import java.util.List;

/**
 * /login &lt;密码&gt; 命令：密码登录（聊天栏与 Dialog 对话框共用入口）。
 *
 * <p>安全：suggest 永远返回空列表——任何参数补全都可能把密码留在
 * 聊天输入框或历史记录中。
 */
public final class LoginCommand implements SimpleCommand {

    private final AuthManager authManager;
    private final MikuMessages messages;

    public LoginCommand(AuthManager authManager, MikuMessages messages) {
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
        authManager.handleLoginCommand(player, args.length > 0 ? args[0] : null);
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
