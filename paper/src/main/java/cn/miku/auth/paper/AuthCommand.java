package cn.miku.auth.paper;

import cn.miku.auth.audit.AuditEntry;
import cn.miku.auth.database.StoredPlayer;
import com.mojang.brigadier.Command;
import com.mojang.brigadier.arguments.StringArgumentType;
import com.mojang.brigadier.builder.LiteralArgumentBuilder;
import io.papermc.paper.command.brigadier.CommandSourceStack;
import io.papermc.paper.command.brigadier.Commands;
import org.bukkit.command.CommandSender;

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
 *
 * <p>查询类子命令把数据库访问丢到异步调度器：命令体跑在主线程，而 SQLite 后端只有一个
 * 工作线程，同步 {@code join()} 会在队列繁忙（例如正在迁移账号）时把整个 tick 卡住。
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
                                    plugin.messages().prefixed("admin.reload.done", Map.of()));
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
                                    CommandSender sender = context.getSource().getSender();
                                    runAsync(plugin, () -> queryAccounts(plugin, sender, target));
                                    return Command.SINGLE_SUCCESS;
                                })))
                .then(Commands.literal("audit")
                        .then(Commands.argument("玩家", StringArgumentType.word())
                                .executes(context -> {
                                    String target = StringArgumentType.getString(context, "玩家");
                                    CommandSender sender = context.getSource().getSender();
                                    runAsync(plugin, () -> queryAudit(plugin, sender, target));
                                    return Command.SINGLE_SUCCESS;
                                })));
    }

    /** 在某 IP 名下账号数的查询后给出汇总行（只给数量，账号明细用代理端命令或直接查库）。 */
    private static void queryAccounts(MikuAuthPlugin plugin, CommandSender sender, String target) {
        Optional<StoredPlayer> found;
        try {
            found = plugin.db().findPlayer(target).join();
        } catch (RuntimeException e) {
            reportFailure(plugin, sender, "账号查询", e);
            return;
        }
        if (found.isEmpty()) {
            sender.sendMessage(plugin.messages().prefixed("admin.accounts.not-found",
                    Map.of("player", target)));
            return;
        }
        StoredPlayer player = found.get();
        String ip = player.lastLoginIp() != null ? player.lastLoginIp() : player.registerIp();
        if (ip == null) {
            sender.sendMessage(plugin.messages().prefixed("admin.accounts.no-ip",
                    Map.of("player", player.nickname())));
            return;
        }
        int count;
        try {
            count = plugin.db().countAccountsByIp(ip).join();
        } catch (RuntimeException e) {
            reportFailure(plugin, sender, "账号数统计", e);
            return;
        }
        sender.sendMessage(plugin.messages().prefixed("admin.accounts.header", Map.of(
                "player", player.nickname(),
                "ip", ip,
                "count", String.valueOf(count))));
    }

    /** 查某昵称最近 15 条审计。 */
    private static void queryAudit(MikuAuthPlugin plugin, CommandSender sender, String target) {
        List<AuditEntry> entries;
        try {
            entries = plugin.db().findAuditByNickname(target, 15).join();
        } catch (RuntimeException e) {
            reportFailure(plugin, sender, "审计查询", e);
            return;
        }
        if (entries.isEmpty()) {
            sender.sendMessage(plugin.messages().prefixed("admin.audit.none", Map.of("key", target)));
            return;
        }
        sender.sendMessage(plugin.messages().prefixed("admin.audit.header", Map.of(
                "key", target,
                "count", String.valueOf(entries.size()))));
        SimpleDateFormat format = new SimpleDateFormat("MM-dd HH:mm:ss");
        for (AuditEntry entry : entries) {
            sender.sendMessage(plugin.messages().component("admin.audit.entry", Map.of(
                    "time", format.format(new Date(entry.createdAt())),
                    "player", entry.nickname() == null ? "-" : entry.nickname(),
                    "ip", entry.ip() == null ? "-" : entry.ip(),
                    "action", entry.action().displayName(),
                    "detail", entry.detail() == null ? "-" : entry.detail())));
        }
    }

    /** 数据库访问丢到异步调度器；调度器已关闭时退回同步执行，至少给玩家一个答复。 */
    private static void runAsync(MikuAuthPlugin plugin, Runnable action) {
        try {
            plugin.getServer().getAsyncScheduler().runNow(plugin, task -> action.run());
        } catch (RuntimeException e) {
            action.run();
        }
    }

    private static void reportFailure(MikuAuthPlugin plugin, CommandSender sender, String what, Exception e) {
        plugin.log().warn("[管理] {} 失败: {}", what, e.toString());
        sender.sendMessage(plugin.messages().prefixed("admin.error",
                Map.of("reason", "内部错误，详见控制台")));
    }
}
