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
import java.util.Set;
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

    /**
     * 未认证玩家也允许执行的子命令（只读或只影响插件自身状态）。
     *
     * <p>其余子命令都是<b>写操作</b>：删密码 / 重置密码 / 清除正版绑定 / 解锁 / 改配额上限 /
     * 迁移账号。未认证玩家绝不能碰 —— 见 {@link #execute(Invocation)} 里的说明。
     */
    private static final Set<String> READ_ONLY_SUB_COMMANDS =
            Set.of("accounts", "audit", "diagnose", "reload");

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
        String sub = args[0].toLowerCase(Locale.ROOT);
        // 未认证玩家的写操作一律拒绝。
        // AuthListener 会在认证前放行 /mikuauth（本意只是允许 reload 之类的只读操作），
        // 而这里若只校验权限节点，在离线模式下（身份键由昵称推导）攻击者只要抢在管理员
        // 之前用管理员的昵称连入，就拿到与管理员相同的 UUID → 权限插件给出同样的权限
        // → /mikuauth setpassword <受害者> <自己的密码> 即可接管他人账号，
        // 且账号接管不需要受害者在线。故写操作必须要求"本连接已通过认证"。
        if (!READ_ONLY_SUB_COMMANDS.contains(sub) && invocation.source() instanceof Player player
                && !plugin.authManager().isAllowed(player)) {
            invocation.source().sendMessage(messages.prefixed("error.must-authenticate", Map.of()));
            return;
        }
        switch (sub) {
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
        invocation.source().sendMessage(plugin.messages().component("admin.diagnose.header",
                Map.of("player", target)));
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
            plugin.database().findAccountsByIp(ip)
                    .thenAccept(accounts -> sendAccountList(source, target, ip, accounts))
                    // 内层 future 的异常必须单独观察：挂在外层链上的 exceptionally 收不到它，
                    // 而 CompletableFuture 会把未观察的异常悄悄吞掉（管理员什么都不显示、日志也没有）
                    .exceptionally(throwable -> {
                        plugin.logger().error("[管理] 账号查询失败: {}", throwable.toString());
                        source.sendMessage(plugin.messages().prefixed("admin.error",
                                Map.of("reason", String.valueOf(throwable.getMessage()))));
                        return null;
                    });
        }).exceptionally(throwable -> {
            source.sendMessage(plugin.messages().prefixed("admin.error",
                    Map.of("reason", String.valueOf(throwable.getMessage()))));
            return null;
        });
    }

    private void sendAccountList(CommandSource source, String target, String ip, List<StoredPlayer> accounts) {
        SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.ROOT);
        // 一律走 messages.component(key, 占位符)：占位符值会被转义，
        // 手写 replace 会绕过这层保护（把可控文本变成可解析的 MiniMessage 标签）
        source.sendMessage(plugin.messages().component("admin.accounts.header",
                Map.of("player", target, "ip", ip, "count", String.valueOf(accounts.size()))));
        for (StoredPlayer account : accounts) {
            source.sendMessage(plugin.messages().component("admin.accounts.entry", Map.of(
                    "player", account.nickname(),
                    "type", account.isPremiumType() ? "正版" : "离线",
                    "password", account.hasPassword() ? "已设置" : "未设置",
                    "time", account.registerTime() > 0
                            ? format.format(new Date(account.registerTime())) : "未知")));
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
                auditAdmin("deletepassword", invocation, target);
                // 会话清理是"释放昵称"的安全前提：失败必须留痕，否则新注册者会被旧会话免密放行
                plugin.database().clearSession(target).exceptionally(throwable -> {
                    plugin.logger().error("[管理] 清除 {} 的会话失败: {}", target, throwable.toString());
                    source.sendMessage(plugin.messages().prefixed("admin.error",
                            Map.of("reason", "会话清理失败，详见控制台")));
                    return null;
                });
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
                auditAdmin("unbind（清除正版绑定）", invocation, target);
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
        plugin.authManager().resetPassword(target, password).thenAccept(updated -> {
            source.sendMessage(plugin.messages().prefixed(
                    updated ? "admin.setpassword.success" : "admin.setpassword.not-found",
                    Map.of("player", target)));
            if (Boolean.TRUE.equals(updated)) {
                // 重置密码是本插件权限最高、最需要追责的操作，必须留痕（此前只有交互式
                // /mikuauth passwd 会记审计，最常用的 setpassword 反而完全不可见）
                auditAdmin("setpassword（重置密码）", invocation, target);
            }
        }).exceptionally(throwable -> {
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
        if (cleared) {
            auditAdmin("unlock（解除临时封禁）", invocation, subject);
        }
    }

    /** 查看登录审计日志：{@code audit <玩家>} 或 {@code audit ip <IP>}。 */
    private void audit(Invocation invocation, String[] args) {
        CommandSource source = invocation.source();
        if (!plugin.config().auditEnabled()) {
            source.sendMessage(plugin.messages().prefixed("admin.audit.disabled", Map.of()));
            return;
        }
        // audit 的用法是 "audit <玩家>" 或 "audit ip <IP>"：只写 "audit ip" 时
        // 旧实现会把它当成"查询昵称为 ip 的玩家"，返回"没有查到 ip 的审计记录"，
        // 管理员会误以为审计为空/坏了
        if ("ip".equalsIgnoreCase(args[1]) && args.length < 3) {
            source.sendMessage(plugin.messages().prefixed("admin.usage",
                    Map.of("usage", "/mikuauth audit ip <IP>")));
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
            source.sendMessage(plugin.messages().component("admin.audit.header",
                    Map.of("key", key, "count", String.valueOf(entries.size()))));
            for (var entry : entries) {
                source.sendMessage(plugin.messages().component("admin.audit.entry", Map.of(
                        "time", format.format(new Date(entry.createdAt())),
                        "player", nvl(entry.nickname()),
                        "ip", nvl(entry.ip()),
                        "action", describeAudit(entry.action()),
                        "detail", nvl(entry.detail()))));
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
            case STALE_ACCOUNT_RELEASED -> "死昵称清理";
            case UNKNOWN -> "未知事件";
        };
    }

    /**
     * 记录管理员写操作（谁、对谁、做了什么）。
     *
     * <p>此前只有交互式 {@code /mikuauth passwd} 会写审计，最常用的 {@code setpassword}
     * 与 {@code deletepassword}/{@code unbind}/{@code unlock}/{@code limit} 全部零留痕 ——
     * 出事时无法追责，与"审计可回答这个号有没有被人动过"的定位不符。
     */
    private void auditAdmin(String action, Invocation invocation, String target) {
        plugin.audit().record(cn.miku.auth.audit.AuditAction.ADMIN_ACTION, target, null, null,
                "管理员 " + actorName(invocation) + " 执行 " + action);
    }

    /** 操作者名称（控制台执行时没有玩家名）。 */
    private static String actorName(Invocation invocation) {
        return invocation.source() instanceof Player player ? player.getUsername() : "控制台";
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
        // 严格校验可选参数：拼错（--dryrun / --dry-run=true / 多余尾参）时报用法并中止，
        // 不能"当成 false 继续跑"—— 那会让管理员以为在试运行，实际已经把数据写进库了
        if (args.length > 4 || (args.length == 4 && !"--dry-run".equalsIgnoreCase(args[3]))) {
            source.sendMessage(plugin.messages().prefixed("admin.usage",
                    Map.of("usage", "/mikuauth migrate <来源> <位置> [--dry-run]")));
            return;
        }
        boolean dryRun = args.length == 4;
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
        String normalized = normalizeLocation(location);
        if (normalized == null) {
            return false;
        }
        for (String prefix : configured.split(",")) {
            String trimmed = prefix.trim();
            if (!trimmed.isEmpty()) {
                String normalizedPrefix = normalizeLocation(trimmed);
                if (normalizedPrefix != null && normalized.startsWith(normalizedPrefix)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * 归一化迁移位置后再做前缀比较，含 {@code ..} 时返回 null（直接拒绝）。
     *
     * <p>直接比较原串可以绕过白名单：白名单 {@code sqlite:/srv/legacy/} 配好后，
     * {@code sqlite:/srv/legacy/../../etc/secret.db} 依然以它开头，但实际指向白名单之外
     * （迁移会以服务端身份连接该库）。Windows 下大小写差异同理，故统一小写。
     */
    private static String normalizeLocation(String location) {
        String value = location.trim().replace('\\', '/');
        if (value.contains("..")) {
            return null;
        }
        for (String prefix : new String[]{"sqlite:", "file:"}) {
            if (value.regionMatches(true, 0, prefix, 0, prefix.length())) {
                String path = value.substring(prefix.length());
                return prefix.toLowerCase(Locale.ROOT)
                        + java.nio.file.Paths.get(path).normalize().toString().replace('\\', '/');
            }
        }
        return value.toLowerCase(Locale.ROOT);
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
                // 改配额上限会影响后续注册能否通过，属于写操作，留痕
                auditAdmin("limit（临时设置每 IP 账号上限=" + value + "）", invocation, "-");
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
