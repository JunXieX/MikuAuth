package cn.miku.auth.command;

import cn.miku.auth.MikuAuthPlugin;
import cn.miku.auth.config.MikuMessages;
import cn.miku.auth.database.StoredPlayer;
import cn.miku.auth.security.PasswordPolicy;
import com.velocitypowered.api.command.CommandSource;
import com.velocitypowered.api.command.SimpleCommand;
import com.velocitypowered.api.proxy.Player;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

/**
 * /mikuauth（别名 /mauth）管理命令。
 *
 * <p>子命令：
 * <ul>
 *   <li>accounts &lt;玩家&gt; —— 查询该玩家 IP 名下的所有账号</li>
 *   <li>audit &lt;玩家&gt; / audit ip &lt;IP&gt; —— 查询登录审计日志（谁、何时、从哪、什么方式）</li>
 *   <li>migrate &lt;来源&gt; &lt;位置&gt; [--dry-run] —— 从其他登录插件迁移账号</li>
 *   <li>diagnose &lt;玩家&gt; —— 回放该昵称的完整进服判定链路</li>
 *   <li>deletepassword &lt;玩家&gt; —— 删除玩家密码（账号回到未注册状态）</li>
 *   <li>setpassword &lt;玩家&gt; &lt;新密码&gt; —— 直接重置密码（不改动账号所有权）</li>
 *   <li>passwd &lt;玩家&gt; —— 交互式重置密码（聊天栏输入，不进命令历史）</li>
 *   <li>unbind &lt;玩家&gt; —— 清除正版绑定（正版玩家改名后遗留的死记录）</li>
 *   <li>unlock &lt;玩家|IP&gt; —— 解除登录失败导致的临时封禁</li>
 *   <li>limit [数量] —— 查看 / 设置每 IP 账号上限</li>
 *   <li>reload —— 重载配置与语言文件</li>
 * </ul>
 */
public final class AdminCommand implements SimpleCommand {

    private static final List<String> SUB_COMMANDS = List.of(
            "accounts", "audit", "migrate", "diagnose", "deletepassword", "setpassword", "passwd",
            "unbind", "unlock", "limit", "reload");

    private final MikuAuthPlugin plugin;

    public AdminCommand(MikuAuthPlugin plugin) {
        this.plugin = plugin;
    }

    @Override
    public void execute(Invocation invocation) {
        String[] args = invocation.arguments();
        MikuMessages messages = plugin.messages();

        if (args.length == 0) {
            sendHelp(invocation, messages);
            return;
        }
        switch (args[0].toLowerCase(Locale.ROOT)) {
            case "accounts" -> requireArgs(invocation, args, 2, "accounts <玩家>",
                    () -> queryAccounts(invocation, args[1]));
            case "audit" -> requireArgs(invocation, args, 2, "audit <玩家> | audit ip <IP>",
                    () -> audit(invocation, args));
            case "migrate" -> requireArgs(invocation, args, 3,
                    "migrate <" + cn.miku.auth.migrate.MigrationSource.usage() + "> <位置> [--dry-run]",
                    () -> migrate(invocation, args));
            case "diagnose" -> requireArgs(invocation, args, 2, "diagnose <玩家>",
                    () -> diagnose(invocation, args[1]));
            case "deletepassword", "delpass" -> requireArgs(invocation, args, 2, "deletepassword <玩家>",
                    () -> deletePassword(invocation, args[1]));
            case "setpassword", "setpass" -> requireArgs(invocation, args, 3, "setpassword <玩家> <新密码>",
                    () -> setPassword(invocation, args));
            case "passwd", "password" -> requireArgs(invocation, args, 2, "passwd <玩家>",
                    () -> passwd(invocation, args[1]));
            case "unbind" -> requireArgs(invocation, args, 2, "unbind <玩家>",
                    () -> unbindPremium(invocation, args[1]));
            case "unlock" -> requireArgs(invocation, args, 2, "unlock <玩家|IP>",
                    () -> unlock(invocation, args[1]));
            case "limit" -> limit(invocation, args);
            case "reload" -> reload(invocation);
            default -> sendHelp(invocation, messages);
        }
    }

    /**
     * 进服诊断：回放指定昵称的完整判定链路，
     * 帮助管理员确认"玩家无法进服"的原因（如与正版玩家 ID 冲突）。
     */
    private void diagnose(Invocation invocation, String target) {
        invocation.source().sendMessage(plugin.renderAdmin(
                plugin.messages().raw("admin.diagnose.header").replace("{player}", target)));
        plugin.authManager().diagnoseAsync(target)
                .thenAccept(report -> {
                    sendLine(invocation, report.dbLine());
                    sendLine(invocation, report.apiLine());
                    sendLine(invocation, report.decisionLine());
                    if (report.conflictLine() != null) {
                        sendLine(invocation, report.conflictLine());
                    }
                })
                .exceptionally(throwable -> {
                    invocation.source().sendMessage(plugin.messages()
                            .prefixed("admin.error", Map.of("reason", String.valueOf(throwable.getMessage()))));
                    return null;
                });
    }

    private void sendLine(Invocation invocation, String line) {
        if (line != null && !line.isEmpty()) {
            invocation.source().sendMessage(plugin.renderAdmin(line));
        }
    }

    // ---------------------------------------------------------------------
    // 子命令
    // ---------------------------------------------------------------------

    /** 查询玩家 IP 名下的所有账号。 */
    private void queryAccounts(Invocation invocation, String target) {
        CommandSource source = invocation.source();
        plugin.database().findPlayer(target).thenAccept(existing -> {
            if (existing.isEmpty()) {
                source.sendMessage(plugin.messages().prefixed("admin.accounts.not-found",
                        Map.of("player", target)));
                return;
            }
            StoredPlayer stored = existing.get();
            String ip = stored.lastLoginIp() != null ? stored.lastLoginIp() : stored.registerIp();
            if (ip == null || ip.isEmpty()) {
                // 没有 IP 记录时直接返回，避免用 NULL 查询得到"0 个账号"的误导性结果
                source.sendMessage(plugin.messages().prefixed("admin.accounts.no-ip",
                        Map.of("player", target)));
                return;
            }
            plugin.database().findAccountsByIp(ip).thenAccept(accounts ->
                    sendAccountList(source, target, ip, accounts));
        }).exceptionally(throwable -> {
            source.sendMessage(plugin.messages().prefixed("admin.error",
                    Map.of("reason", String.valueOf(throwable.getMessage()))));
            return null;
        });
    }

    private void sendAccountList(CommandSource source, String target, String ip, List<StoredPlayer> accounts) {
        SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.ROOT);
        StringBuilder lines = new StringBuilder(
                plugin.messages().raw("admin.accounts.header")
                        .replace("{player}", target)
                        .replace("{ip}", ip)
                        .replace("{count}", String.valueOf(accounts.size())));
        for (StoredPlayer account : accounts) {
            lines.append('\n').append(plugin.messages().raw("admin.accounts.entry")
                    .replace("{player}", account.nickname())
                    .replace("{type}", account.isPremiumType() ? "正版" : "离线")
                    .replace("{password}", account.hasPassword() ? "已设置" : "未设置")
                    .replace("{time}", account.registerTime() > 0
                            ? format.format(new Date(account.registerTime())) : "未知"));
        }
        // 多行文本逐行渲染，保持 MiniMessage 颜色标签生效
        for (String line : lines.toString().split("\n")) {
            source.sendMessage(plugin.renderAdmin(line));
        }
    }

    /**
     * 删除玩家密码：账号回到"未注册"状态（定位是"释放昵称"，日常重置请用 setpassword）。
     *
     * <p>同时清除该账号的同 IP 会话——否则该昵称被重新注册后，
     * 旧会话仍会免密放行，等于把新账号交给了同一 IP 上的其他人。
     */
    private void deletePassword(Invocation invocation, String target) {
        CommandSource source = invocation.source();
        plugin.database().deletePassword(target).thenAccept(success -> {
            String key = success ? "admin.deletepassword.success" : "admin.deletepassword.not-found";
            source.sendMessage(plugin.messages().prefixed(key, Map.of("player", target)));
            if (success) {
                plugin.database().clearSession(target);
            }
        }).exceptionally(throwable -> {
            source.sendMessage(plugin.messages().prefixed("admin.error",
                    Map.of("reason", String.valueOf(throwable.getMessage()))));
            return null;
        });
    }

    /**
     * 清除正版绑定：把账号降级为离线账号。
     *
     * <p>用于正版玩家在 Mojang 改名后遗留的"死记录"——旧昵称会持续被强制正版会话校验，
     * 而 Mojang 已不再解析该昵称，导致该昵称永久不可用（fail-closed 下也无他人可用）。
     */
    private void unbindPremium(Invocation invocation, String target) {
        CommandSource source = invocation.source();
        plugin.database().clearPremiumBinding(target).thenAccept(changed -> {
            String key = changed ? "admin.unbind.success" : "admin.unbind.not-found";
            source.sendMessage(plugin.messages().prefixed(key, Map.of("player", target)));
            if (changed) {
                // 让缓存中的决策立即失效，无需等玩家重连
                plugin.authManager().invalidateLoginDecision(target);
            }
        }).exceptionally(throwable -> {
            source.sendMessage(plugin.messages().prefixed("admin.error",
                    Map.of("reason", String.valueOf(throwable.getMessage()))));
            return null;
        });
    }

    /**
     * 交互式重置密码（推荐用法）：密码在聊天栏输入，不经过命令行。
     *
     * <p>为什么需要它：Velocity 会把完整命令行写入 {@code .console_history}
     * （格式为"时间戳:命令"），所以 {@code setpassword <玩家> <密码>} 的明文密码
     * 会落到磁盘上；从游戏内执行时也会留在玩家客户端的历史里。
     */
    private void passwd(Invocation invocation, String target) {
        if (!(invocation.source() instanceof Player admin)) {
            invocation.source().sendMessage(plugin.messages().prefixed(
                    "admin.passwd.console-unsupported", Map.of()));
            return;
        }
        plugin.authManager().beginPasswordReset(admin, target);
        admin.sendMessage(plugin.messages().prefixed("admin.passwd.prompt",
                Map.of("player", target)));
    }

    /**
     * 重置玩家密码：不校验旧密码，直接写入新哈希。
     *
     * <p>与 {@code deletepassword} 的区别很关键：删密码会让账号回到"未注册"状态，
     * 同 IP 的任何人随后都能抢注该昵称（所有权丢失）；重置密码则保留账号，
     * 并同步清除该账号的同 IP 会话免密记录。
     */
    private void setPassword(Invocation invocation, String[] args) {
        CommandSource source = invocation.source();
        String target = args[1];
        String password = args[2];
        // 与玩家自助改密共用同一套密码策略，避免"管理员能设出玩家设不了的密码"
        PasswordPolicy.Violation violation = PasswordPolicy.check(plugin.config(), password);
        if (violation != null) {
            source.sendMessage(plugin.messages().prefixed(violation.messageKey(), violation.placeholders()));
            return;
        }
        plugin.authManager().resetPassword(target, password).thenAccept(updated ->
                source.sendMessage(plugin.messages().prefixed(
                        updated ? "admin.setpassword.success" : "admin.setpassword.not-found",
                        Map.of("player", target)))
        ).exceptionally(throwable -> {
            source.sendMessage(plugin.messages().prefixed("admin.error",
                    Map.of("reason", String.valueOf(throwable.getMessage()))));
            return null;
        });
    }

    /** 解除某玩家 / 某 IP 的临时封禁。 */
    private void unlock(Invocation invocation, String subject) {
        boolean cleared = plugin.authManager().unlock(subject);
        invocation.source().sendMessage(plugin.messages().prefixed(
                cleared ? "admin.unlock.success" : "admin.unlock.not-found",
                Map.of("subject", subject)));
    }

    /** 查看登录审计日志：{@code audit <玩家>} 或 {@code audit ip <IP>}。 */
    private void audit(Invocation invocation, String[] args) {
        CommandSource source = invocation.source();
        if (!plugin.config().auditEnabled()) {
            source.sendMessage(plugin.messages().prefixed("admin.audit.disabled", Map.of()));
            return;
        }
        boolean byIp = args.length >= 3 && "ip".equalsIgnoreCase(args[1]);
        String key = byIp ? args[2] : args[1];
        int limit = plugin.config().auditQueryLimit();
        CompletableFuture<List<cn.miku.auth.audit.AuditEntry>> future = byIp
                ? plugin.database().findAuditByIp(key, limit)
                : plugin.database().findAuditByNickname(key, limit);
        future.thenAccept(entries -> {
            if (entries.isEmpty()) {
                source.sendMessage(plugin.messages().prefixed("admin.audit.none",
                        Map.of("key", key)));
                return;
            }
            SimpleDateFormat format = new SimpleDateFormat("MM-dd HH:mm:ss", Locale.ROOT);
            source.sendMessage(plugin.renderAdmin(plugin.messages().raw("admin.audit.header")
                    .replace("{key}", key)
                    .replace("{count}", String.valueOf(entries.size()))));
            for (var entry : entries) {
                source.sendMessage(plugin.renderAdmin(plugin.messages().raw("admin.audit.entry")
                        .replace("{time}", format.format(new Date(entry.createdAt())))
                        .replace("{player}", nvl(entry.nickname()))
                        .replace("{ip}", nvl(entry.ip()))
                        .replace("{action}", describeAudit(entry.action()))
                        .replace("{detail}", nvl(entry.detail()))));
            }
        }).exceptionally(throwable -> {
            source.sendMessage(plugin.messages().prefixed("admin.error",
                    Map.of("reason", String.valueOf(throwable.getMessage()))));
            return null;
        });
    }

    /** 审计事件类型 → 中文说明（管理员看日志时不必对照枚举名）。 */
    private static String describeAudit(cn.miku.auth.audit.AuditAction action) {
        return switch (action) {
            case LOGIN_SUCCESS -> "密码登录";
            case LOGIN_PREMIUM -> "正版免密";
            case LOGIN_BEDROCK -> "基岩免密";
            case LOGIN_SESSION -> "会话免密";
            case LOGIN_FAIL -> "密码错误";
            case REGISTER -> "注册";
            case CHANGE_PASSWORD -> "改密";
            case KICK_TIMEOUT -> "超时踢出";
            case REJECT_PREMIUM_FAILED -> "正版验证失败";
            case REJECT_NAME_SNIPE -> "昵称抢注";
            case REJECT_IP_LIMIT -> "IP 超限";
            case ADMIN_ACTION -> "管理员操作";
            case MIGRATE -> "账号迁移";
        };
    }

    private static String nvl(String value) {
        return value == null || value.isEmpty() ? "-" : value;
    }

    /**
     * 从其他登录插件迁移账号：{@code migrate <来源> <位置> [--dry-run]}。
     *
     * <p>强烈建议先跑一次 {@code --dry-run} 核对数量，再正式执行。
     */
    private void migrate(Invocation invocation, String[] args) {
        CommandSource source = invocation.source();
        var parsed = cn.miku.auth.migrate.MigrationSource.parse(args[1]);
        if (parsed == null) {
            source.sendMessage(plugin.messages().prefixed("admin.migrate.unknown-source",
                    Map.of("source", args[1],
                            "sources", cn.miku.auth.migrate.MigrationSource.usage())));
            return;
        }
        String location = args[2];
        // 位置参数会让服务器以本机身份连接目标库（可读本机文件、也可连任意 MySQL），
        // 因此支持用 config 的 migrate.allowed-prefixes 做前缀白名单（留空则不限制）
        if (!locationAllowed(location)) {
            source.sendMessage(plugin.messages().prefixed("admin.migrate.not-allowed",
                    Map.of("location", location,
                            "allowed", plugin.config().migrateAllowedPrefixes())));
            return;
        }
        boolean dryRun = args.length >= 4 && "--dry-run".equalsIgnoreCase(args[3]);
        source.sendMessage(plugin.messages().prefixed("admin.migrate.start",
                Map.of("source", parsed.displayName(),
                        "mode", dryRun ? "试运行（不写入）" : "正式执行")));
        plugin.migrator().migrateAsync(parsed, location, dryRun).whenComplete((report, error) -> {
            if (error != null) {
                source.sendMessage(plugin.messages().prefixed("admin.migrate.failed",
                        Map.of("reason", sanitizeFailure(error))));
                return;
            }
            source.sendMessage(plugin.messages().prefixed("admin.migrate.done", Map.of(
                    "source", report.source(),
                    "total", String.valueOf(report.total()),
                    "imported", String.valueOf(report.imported()),
                    "skipped", String.valueOf(report.skipped()),
                    "noPassword", String.valueOf(report.noPassword()))));
            if (report.noPassword() > 0) {
                source.sendMessage(plugin.messages().prefixed("admin.migrate.no-password-tip",
                        Map.of("count", String.valueOf(report.noPassword()))));
            }
            if (report.hasFailures()) {
                for (String failure : report.failures()) {
                    source.sendMessage(plugin.renderAdmin("<red>×</red> <gray>" + failure + "</gray>"));
                }
            }
            if (dryRun) {
                source.sendMessage(plugin.messages().prefixed("admin.migrate.dry-run-tip", Map.of()));
            } else if (report.imported() > 0) {
                source.sendMessage(plugin.messages().prefixed("admin.migrate.security-tip", Map.of()));
            }
        });
    }

    /** 迁移位置是否被允许（未配置白名单时不限制）。 */
    private boolean locationAllowed(String location) {
        String configured = plugin.config().migrateAllowedPrefixes();
        if (configured == null || configured.isBlank()) {
            return true;
        }
        for (String prefix : configured.split(",")) {
            String trimmed = prefix.trim();
            if (!trimmed.isEmpty() && location.startsWith(trimmed)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 失败原因脱敏。
     *
     * <p>实测 MariaDB 驱动在连接失败时只回显 host/port（不含口令），
     * 但这里仍做一次遮蔽作为纵深防御——异常文案随驱动版本变化，
     * 而回显目的地是聊天栏与控制台日志。
     */
    private static String sanitizeFailure(Throwable error) {
        String raw = error.getMessage() == null
                ? error.getClass().getSimpleName()
                : error.getMessage();
        return raw.replaceAll("(?i)password=[^&\\s]*", "password=***");
    }

    /** 查看 / 设置 IP 限号。 */
    private void limit(Invocation invocation, String[] args) {
        if (args.length >= 2) {
            try {
                int value = Integer.parseInt(args[1]);
                if (value < 0) {
                    throw new NumberFormatException("负数");
                }
                plugin.config().setMaxAccountsPerIpOverride(value);
                invocation.source().sendMessage(plugin.messages().prefixed("admin.limit.set",
                        Map.of("limit", String.valueOf(value))));
            } catch (NumberFormatException e) {
                invocation.source().sendMessage(plugin.messages().prefixed("admin.limit.invalid",
                        Map.of("input", args[1])));
            }
            return;
        }
        invocation.source().sendMessage(plugin.messages().prefixed("admin.limit.current",
                Map.of("limit", String.valueOf(plugin.config().maxAccountsPerIp()))));
    }

    /** 重载配置与语言文件（含正版验证源与缓存参数）。 */
    private void reload(Invocation invocation) {
        try {
            plugin.reloadConfig();
            invocation.source().sendMessage(plugin.messages().prefixed("admin.reload.done", Map.of()));
        } catch (Exception e) {
            invocation.source().sendMessage(plugin.messages().prefixed("admin.error",
                    Map.of("reason", String.valueOf(e.getMessage()))));
        }
    }

    // ---------------------------------------------------------------------
    // 工具
    // ---------------------------------------------------------------------

    private void requireArgs(Invocation invocation, String[] args, int required,
                             String usage, Runnable action) {
        if (args.length < required) {
            invocation.source().sendMessage(plugin.messages().prefixed("admin.usage",
                    Map.of("usage", "/mikuauth " + usage)));
            return;
        }
        action.run();
    }

    private void sendHelp(Invocation invocation, MikuMessages messages) {
        for (String line : messages.rawList("admin.help")) {
            invocation.source().sendMessage(plugin.renderAdmin(line));
        }
    }

    @Override
    public List<String> suggest(Invocation invocation) {
        String[] args = invocation.arguments();
        if (args.length <= 1) {
            return SUB_COMMANDS.stream()
                    .filter(sub -> args.length == 0 || sub.startsWith(args[0].toLowerCase(Locale.ROOT)))
                    .toList();
        }
        // 敏感查询不补全玩家名（避免枚举账号）
        return List.of();
    }

    @Override
    public boolean hasPermission(Invocation invocation) {
        return invocation.source().hasPermission("mikuauth.admin");
    }
}
