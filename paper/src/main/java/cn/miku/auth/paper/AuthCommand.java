package cn.miku.auth.paper;

import cn.miku.auth.audit.AuditEntry;
import cn.miku.auth.database.StoredPlayer;
import com.mojang.brigadier.Command;
import com.mojang.brigadier.arguments.StringArgumentType;
import com.mojang.brigadier.builder.LiteralArgumentBuilder;
import io.papermc.paper.command.brigadier.CommandSourceStack;
import io.papermc.paper.command.brigadier.Commands;
import net.kyori.adventure.text.Component;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * {@code /mikuauth}（别名 {@code /mauth}）管理命令。
 *
 * <p>只保留运维真正需要的四件事：重载、解锁、查账号、查审计。账号增删改一律建议直接改库 ——
 * 少一个入口就少一类误操作。
 *
 * <p>权限：读操作要 {@code mikuauth.admin}，写操作（unlock / reload）要
 * {@code mikuauth.admin.write}。文本键与代理端共用同一份 {@code messages.yml}。
 */
final class AuthCommand {

    private AuthCommand() {
    }

    static LiteralArgumentBuilder<CommandSourceStack> build(MikuAuthPlugin plugin) {
        return Commands.literal("mikuauth")
                .requires(source -> source.getSender().hasPermission("mikuauth.admin")
                        || source.getSender().hasPermission("mikuauth.admin.write"))
                // 只敲 /mikuauth 时给出用法，而不是 Brigadier 的 "Unknown or incomplete command"
                .executes(context -> {
                    context.getSource().getSender().sendMessage(plugin.messages().prefixed("admin.usage",
                            Map.of("usage", "/mikuauth reload | unlock <玩家或IP> | accounts <玩家> | audit <玩家>")));
                    return Command.SINGLE_SUCCESS;
                })
                .then(Commands.literal("reload")
                        .requires(source -> source.getSender().hasPermission("mikuauth.admin.write"))
                        .executes(context -> {
                            plugin.reload();
                            context.getSource().getSender().sendMessage(
                                    plugin.messages().prefixed("admin.reload", Map.of()));
                            return Command.SINGLE_SUCCESS;
                        }))
                .then(Commands.literal("unlock")
                        .requires(source -> source.getSender().hasPermission("mikuauth.admin.write"))
                        .then(Commands.argument("目标", StringArgumentType.word())
                                .executes(context -> {
                                    String subject = StringArgumentType.getString(context, "目标");
                                    boolean cleared = plugin.throttle().unlock(subject);
                                    context.getSource().getSender().sendMessage(plugin.messages().prefixed(
                                            cleared ? "admin.unlock.success" : "admin.unlock.not-found",
                                            Map.of("subject", subject)));
                                    return Command.SINGLE_SUCCESS;
                                })))
                .then(Commands.literal("accounts")
                        .then(Commands.argument("玩家", StringArgumentType.word())
                                .executes(context -> {
                                    String target = StringArgumentType.getString(context, "玩家");
                                    Optional<StoredPlayer> found = plugin.db().findPlayer(target).join();
                                    if (found.isEmpty()) {
                                        context.getSource().getSender().sendMessage(plugin.messages().prefixed(
                                                "admin.accounts.not-found", Map.of("player", target)));
                                        return Command.SINGLE_SUCCESS;
                                    }
                                    StoredPlayer player = found.get();
                                    String ip = player.lastLoginIp() != null ? player.lastLoginIp() : player.registerIp();
                                    if (ip == null) {
                                        context.getSource().getSender().sendMessage(plugin.messages().prefixed(
                                                "admin.accounts.no-ip", Map.of("player", player.nickname())));
                                        return Command.SINGLE_SUCCESS;
                                    }
                                    int count = plugin.db().countAccountsByIp(ip).join();
                                    context.getSource().getSender().sendMessage(plugin.messages().prefixed(
                                            "admin.accounts.header", Map.of(
                                                    "player", player.nickname(),
                                                    "ip", ip,
                                                    "count", String.valueOf(count))));
                                    return Command.SINGLE_SUCCESS;
                                })))
                .then(Commands.literal("audit")
                        .then(Commands.argument("玩家", StringArgumentType.word())
                                .executes(context -> {
                                    String target = StringArgumentType.getString(context, "玩家");
                                    List<AuditEntry> entries = plugin.db().findAuditByNickname(target, 15).join();
                                    if (entries.isEmpty()) {
                                        context.getSource().getSender().sendMessage(plugin.messages().prefixed(
                                                "admin.audit.empty", Map.of("key", target)));
                                        return Command.SINGLE_SUCCESS;
                                    }
                                    context.getSource().getSender().sendMessage(plugin.messages().prefixed(
                                            "admin.audit.header", Map.of(
                                                    "key", target,
                                                    "count", String.valueOf(entries.size()))));
                                    SimpleDateFormat format = new SimpleDateFormat("MM-dd HH:mm:ss");
                                    for (AuditEntry entry : entries) {
                                        context.getSource().getSender().sendMessage(plugin.messages().component(
                                                "admin.audit.entry", Map.of(
                                                        "time", format.format(new Date(entry.createdAt())),
                                                        "player", entry.nickname() == null ? "-" : entry.nickname(),
                                                        "ip", entry.ip() == null ? "-" : entry.ip(),
                                                        "action", entry.action().name(),
                                                        "detail", entry.detail() == null ? "-" : entry.detail())));
                                    }
                                    return Command.SINGLE_SUCCESS;
                                })));
    }
}
