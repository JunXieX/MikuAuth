package cn.miku.auth.command;

import cn.miku.auth.auth.AuthManager;
import cn.miku.auth.config.MikuMessages;
import com.velocitypowered.api.command.SimpleCommand;
import com.velocitypowered.api.proxy.Player;

import java.util.List;
import java.util.Map;

/**
 * /changepassword &lt;旧密码&gt; &lt;新密码&gt; &lt;确认新密码&gt;：玩家自助修改密码。
 *
 * <p>与 /login、/register 一致：{@code suggest} 永远返回空列表——
 * 任何参数补全都可能把密码留在聊天输入框或历史记录中。
 *
 * <p>改密成功后该账号的同 IP 会话免密记录会被清除，旧会话不再免密。
 */
public final class ChangePasswordCommand implements SimpleCommand {

    private final AuthManager authManager;
    private final MikuMessages messages;

    public ChangePasswordCommand(AuthManager authManager, MikuMessages messages) {
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
        if (args.length < 3) {
            invocation.source().sendMessage(messages.prefixed("changepassword.usage", Map.of()));
            return;
        }
        authManager.handleChangePasswordCommand(player, args[0], args[1], args[2]);
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
