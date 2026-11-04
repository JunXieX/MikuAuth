package cn.miku.auth.paper;

import com.mojang.brigadier.Command;
import com.mojang.brigadier.builder.LiteralArgumentBuilder;
import com.mojang.brigadier.arguments.StringArgumentType;
import io.papermc.paper.command.brigadier.CommandSourceStack;
import io.papermc.paper.command.brigadier.Commands;
import net.kyori.adventure.text.Component;

import java.util.Map;

/**
 * {@code /mikuauth}（别名 {@code /mauth}）管理命令。
 *
 * <p>只保留运维真正需要的四件事：重载、解锁、查名下账号、查审计。
 * 账号增删改一律建议直接改库或走 {@code /mikuauth} 之外的流程 —— 少一个入口就少一类误操作。
 *
 * <p>权限：读操作要 {@code mikuauth.admin}，写操作（unlock / reload）要 {@code mikuauth.admin.write}。
 */
final class AuthCommand {

    private AuthCommand() {
    }

    static LiteralArgumentBuilder<CommandSourceStack> build(MikuAuthPlugin plugin) {
        return Commands.literal("mikuauth")
                .requires(source -> source.getSender().hasPermission("mikuauth.admin")
                        || source.getSender().hasPermission("mikuauth.admin.write"))
                .then(Commands.literal("reload")
                        .requires(source -> source.getSender().hasPermission("mikuauth.admin.write"))
                        .executes(context -> {
                            plugin.reload();
                            context.getSource().getSender().sendMessage(plugin.messages().prefixed("admin.reload", Map.of()));
                            return Command.SINGLE_SUCCESS;
                        }))
                .then(Commands.literal("unlock")
                        .requires(source -> source.getSender().hasPermission("mikuauth.admin.write"))
                        .then(Commands.argument("目标", StringArgumentType.word())
                                .executes(context -> {
                                    String subject = StringArgumentType.getString(context, "目标");
                                    boolean cleared = plugin.gate().unlock(subject);
                                    context.getSource().getSender().sendMessage(plugin.messages().prefixed(
                                            cleared ? "admin.unlock-success" : "admin.unlock-none",
                                            Map.of("subject", subject)));
                                    return Command.SINGLE_SUCCESS;
                                })))
                .then(Commands.literal("accounts")
                        .then(Commands.argument("玩家", StringArgumentType.word())
                                .executes(context -> {
                                    String target = StringArgumentType.getString(context, "玩家");
                                    Store.Account account = plugin.store().find(target);
                                    if (account == null) {
                                        context.getSource().getSender().sendMessage(plugin.messages().prefixed(
                                                "admin.accounts-none", Map.of("player", target)));
                                        return Command.SINGLE_SUCCESS;
                                    }
                                    int total = plugin.store().countByIp(plugin.store().lastIp(account.nicknameLower()));
                                    context.getSource().getSender().sendMessage(plugin.messages().prefixed(
                                            "admin.accounts-header",
                                            Map.of("player", account.nickname(), "count", String.valueOf(total))));
                                    return Command.SINGLE_SUCCESS;
                                })))
                .then(Commands.literal("audit")
                        .then(Commands.argument("玩家", StringArgumentType.word())
                                .executes(context -> {
                                    String target = StringArgumentType.getString(context, "玩家");
                                    var lines = plugin.store().recentAudit(target, 15);
                                    if (lines.isEmpty()) {
                                        context.getSource().getSender().sendMessage(plugin.messages().prefixed(
                                                "admin.audit-none", Map.of("player", target)));
                                        return Command.SINGLE_SUCCESS;
                                    }
                                    context.getSource().getSender().sendMessage(plugin.messages().prefixed(
                                            "admin.audit-header",
                                            Map.of("player", target, "count", String.valueOf(lines.size()))));
                                    for (String line : lines) {
                                        context.getSource().getSender().sendMessage(Component.text(line));
                                    }
                                    return Command.SINGLE_SUCCESS;
                                })));
    }
}
