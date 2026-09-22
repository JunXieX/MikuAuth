package cn.miku.auth;

import cn.miku.auth.auth.AuthListener;
import cn.miku.auth.auth.AuthManager;
import cn.miku.auth.auth.DialogCloseListener;
import cn.miku.auth.command.AdminCommand;
import cn.miku.auth.command.ChangePasswordCommand;
import cn.miku.auth.command.CloseDialogCommand;
import cn.miku.auth.command.LoginCommand;
import cn.miku.auth.command.RegisterCommand;
import cn.miku.auth.config.MikuConfig;
import cn.miku.auth.config.MikuMessages;
import cn.miku.auth.audit.AuditLogger;
import cn.miku.auth.audit.BackendKickLog;
import cn.miku.auth.audit.PremiumConflictLog;
import cn.miku.auth.database.DatabaseManager;
import cn.miku.auth.migrate.AccountMigrator;
import cn.miku.auth.dialog.DialogService;
import cn.miku.auth.display.DisplayManager;
import cn.miku.auth.premium.PremiumService;
import cn.miku.auth.util.TextUtil;
import com.google.inject.Inject;
import com.velocitypowered.api.command.CommandManager;
import com.velocitypowered.api.command.CommandMeta;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.proxy.ProxyInitializeEvent;
import com.velocitypowered.api.event.proxy.ProxyShutdownEvent;
import com.velocitypowered.api.plugin.Dependency;
import com.velocitypowered.api.plugin.Plugin;
import com.velocitypowered.api.plugin.annotation.DataDirectory;
import com.velocitypowered.api.proxy.ProxyServer;
import net.kyori.adventure.text.Component;
import org.slf4j.Logger;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Duration;

/**
 * MikuAuth —— Velocity 登录验证插件。
 *
 * <p>功能总览：
 * <ul>
 *   <li>Java 正版免密：并发查询 Mojang / Ashcon / WPME 三个验证源，任一确认即强制
 *       正版会话校验，校验通过后免密进入；</li>
 *   <li>基岩版免密：Floodgate API 识别后直接放行；</li>
 *   <li>离线账号：注册 / 登录支持原版 Dialog 对话框（PacketEvents，可用
 *       {@code dialog.enabled} 关闭以统一走聊天栏），支持自助改密，
 *       登录后一段时间内<b>同 IP 免密</b>；</li>
 *   <li>安全风控：同 IP 提交限速、跨会话失败计数与临时封禁；</li>
 *   <li>Title + BossBar 提示；Dialog 打开期间静默，关闭后恢复；</li>
 *   <li>SQLite / MariaDB 存储：按 IP 限制账号数、名下账号查询、密码重置与删除；</li>
 *   <li>全部游戏内文本可在 messages.yml 自定义（含完整中文注释）。</li>
 * </ul>
 */
@Plugin(
        id = "mikuauth",
        name = "MikuAuth",
        version = MikuAuthPlugin.VERSION,
        description = "Velocity 登录验证插件：正版多源免密 / 基岩版免密 / Dialog 对话框登录（可开关）/ 同 IP 会话免密 / SQLite + MariaDB",
        authors = {"JunXieX"},
        dependencies = {
                // 强依赖：packetevents-velocity 缺失时 Velocity 不会加载本插件
                //（对话框菜单与登录流程均基于 PacketEvents 实现）
                @Dependency(id = "packetevents"),
                // 可选：基岩版识别依赖 floodgate（未安装时基岩版走常规验证）。
                // 注意：Geyser 由 Floodgate 自身声明依赖，本插件无需重复声明。
                @Dependency(id = "floodgate", optional = true)
        }
)
public final class MikuAuthPlugin {

    /**
     * 插件版本：唯一的版本号来源（{@code pom.xml} 需同步修改）。
     * 同时用于 {@code @Plugin} 注解与对外请求的 User-Agent，避免多处硬编码走样。
     */
    public static final String VERSION = "2.6.0";

    private final ProxyServer server;
    private final Logger logger;
    private final Path dataDirectory;

    private final MikuConfig config = new MikuConfig();
    private final MikuMessages messages = new MikuMessages();

    private DatabaseManager database;
    private PremiumService premiumService;
    private DialogService dialogService;
    private DisplayManager display;
    private AuthManager authManager;
    /** 昵称冲突记录文件（记"同名冲突被顶下线"；关服时需排空写盘队列）。 */
    private PremiumConflictLog conflictLog;
    /** 后端拒绝进入记录文件（记目标服给出的踢出原因；关服时需排空写盘队列）。 */
    private BackendKickLog backendKickLog;
    /** 账号迁移器。 */
    private AccountMigrator migrator;
    /** 审计记录器：认证流程、迁移器与管理命令的写操作共用同一个实例。 */
    private AuditLogger auditLogger;
    private boolean packetListenerRegistered;
    /** 初始化失败或强依赖缺失时置位：此时不注册任何监听、命令与任务。 */
    private volatile boolean disabled;

    @Inject
    public MikuAuthPlugin(ProxyServer server, Logger logger, @DataDirectory Path injected) {
        this.server = server;
        this.logger = logger;
        // 数据目录固定为 plugins/MikuAuth（@DataDirectory 注入的是 plugins/<插件id>，名称由插件决定）。
        // 注意：Windows 上两者等价，Linux 上大小写敏感，因此文档统一按 plugins/MikuAuth 描述。
        this.dataDirectory = injected.getParent().resolve("MikuAuth");
    }


    // ---------------------------------------------------------------------
    // 初始化
    // ---------------------------------------------------------------------

    @Subscribe
    public void onProxyInitialize(ProxyInitializeEvent event) {
        // 初始化入口必须 catch Throwable：依赖类链接失败是 Error 而非 Exception，
        // 若不兜底会导致日志缺失、状态不一致
        try {
            initialize();
        } catch (Throwable t) {
            logger.error("[MikuAuth] 初始化失败: {}", t.getMessage(), t);
            disabled = true;
        }
    }

    /**
     * 初始化。强依赖校验失败（缺 PacketEvents / 缺认证服）时直接停止加载：
     * 不注册监听、不注册命令、不启动心跳，插件保持非工作状态。
     */
    private void initialize() throws IOException, java.sql.SQLException {
        // 1) PacketEvents 强依赖：@Dependency 已保证缺失时不加载，
        //    此处再校验 API 实例就绪（安装的是否为官方完整版）
        com.github.retrooper.packetevents.PacketEventsAPI<?> pe;
        try {
            pe = com.github.retrooper.packetevents.PacketEvents.getAPI();
        } catch (Throwable t) {
            pe = null;
        }
        if (pe == null || !pe.isLoaded()) {
            logger.error("[MikuAuth] 未检测到可用的 PacketEvents！请安装官方完整版 packetevents-velocity 插件，"
                    + "MikuAuth 将保持停用。");
            disabled = true;
            return;
        }

        // 2) 配置与语言文件
        config.load(dataDirectory, logger);
        messages.load(dataDirectory, logger);

        // 3) 认证服强校验：找不到 auth-server 则插件停用
        //    （认证流程必须经由隔离的认证服完成，玩家绝不允许落在真实服中认证）
        if (server.getServer(config.authServer()).isEmpty()) {
            logger.error("[MikuAuth] 未在 velocity.toml 的 [servers] 中找到认证服 '{}'，MikuAuth 已停用！"
                            + "请先在 velocity.toml 中登记认证服（如 limbo），再将 auth-server 指向它。",
                    config.authServer());
            disabled = true;
            return;
        }

        // 4) 认证后目标服强校验：必须存在至少一个非认证服作为玩家去向，
        //    否则玩家认证完成后无处可去（滞留认证服）
        boolean hasPostAuthTarget = false;
        String fallbackName = config.fallbackServer();
        if (fallbackName != null && !fallbackName.isEmpty()) {
            hasPostAuthTarget = server.getServer(fallbackName).isPresent();
        }
        if (!hasPostAuthTarget) {
            for (String name : server.getConfiguration().getAttemptConnectionOrder()) {
                if (!name.equalsIgnoreCase(config.authServer()) && server.getServer(name).isPresent()) {
                    hasPostAuthTarget = true;
                    break;
                }
            }
        }
        if (!hasPostAuthTarget) {
            logger.error("[MikuAuth] 未找到任何认证后目标服务器（fallback-server 与 velocity.toml 的 "
                    + "try 列表均无可用非认证服），MikuAuth 已停用！"
                    + "请在 velocity.toml 中登记至少一个正式服务器并加入 try 列表，"
                    + "或在 config.yml 中配置 fallback-server。");
            disabled = true;
            return;
        }

        database = new DatabaseManager(dataDirectory, config, logger);
        premiumService = new PremiumService(config, logger);
        dialogService = new DialogService(config, messages, logger);
        display = new DisplayManager(config, messages);
        // 审计记录器：认证流程、迁移器与管理命令的写操作共用同一个实例
        auditLogger = new AuditLogger(database, config, logger);
        // 昵称冲突记录文件（记录"同名冲突被顶下线"；会话校验失败的连接不产生事件，不会写到这里）
        conflictLog = new PremiumConflictLog(dataDirectory, config, logger);
        // 后端拒绝进入记录文件（目标服给出的踢出原因；同一原因也会转发到玩家聊天栏）
        backendKickLog = new BackendKickLog(dataDirectory, config, logger);
        authManager = new AuthManager(this, server, logger, config, messages,
                database, premiumService, dialogService, display, auditLogger, conflictLog, backendKickLog);
        migrator = new AccountMigrator(database, auditLogger, logger);

        // 事件监听
        server.getEventManager().register(this, new AuthListener(server, logger, config, authManager));

        // 命令注册
        registerCommands();

        // PacketEvents 监听（对话框关闭兜底检测）
        registerPacketListener();

        // 心跳：超时踢出 + Title/BossBar 刷新
        server.getScheduler().buildTask(this, () -> {
                    try {
                        authManager.tick();
                    } catch (Throwable t) {
                        logger.warn("[MikuAuth] 心跳异常: {}", t.getMessage());
                    }
                })
                .delay(Duration.ofSeconds(1))
                .repeat(Duration.ofSeconds(1))
                .schedule();

        // 定期清理：过期会话（数据库行）与审计日志
        server.getScheduler().buildTask(this, () -> {
                    try {
                        database.purgeExpiredSessions();
                        authManager.purgeAuditLogs();
                    } catch (Throwable ignored) {
                        // 清理失败不影响主流程
                    }
                })
                .delay(Duration.ofMinutes(1))
                .repeat(Duration.ofMinutes(5))
                .schedule();

        logger.info("[MikuAuth] v{} 已加载 — 正版验证: {} | 基岩版(Floodgate): {} | 认证服: {}",
                VERSION,
                premiumService.hasResolvers() ? "启用" : "禁用",
                config.bedrockAutoLogin() ? "启用" : "禁用",
                config.authServer());
        // Dialog 菜单：关闭时明确提示"已按聊天栏模式运行"，避免服主以为插件没生效
        logger.info("[MikuAuth] Dialog 对话框菜单: {}",
                config.dialogEnabled()
                        ? "启用（客户端 1.21.6+ 且 PacketEvents 就绪时使用，否则自动降级为聊天栏）"
                        : "已关闭（全部玩家使用聊天栏 /login、/register）");
        if (conflictLog.enabled()) {
            logger.info("[MikuAuth] 昵称冲突记录: {}"
                            + "（同名连接被顶下线时写入，便于事后核对）",
                    conflictLog.file());
        }
        if (backendKickLog.enabled()) {
            logger.info("[MikuAuth] 后端拒绝记录: {}"
                            + "（玩家被目标服踢回时写入，原因同时转发给玩家）",
                    backendKickLog.file());
        }
    }

    /** 注册玩家命令与管理命令。 */
    private void registerCommands() {
        CommandManager commandManager = server.getCommandManager();

        CommandMeta loginMeta = commandManager.metaBuilder("login")
                .plugin(this)
                .aliases(config.loginAliases().toArray(new String[0]))
                .build();
        commandManager.register(loginMeta, new LoginCommand(authManager, messages));

        CommandMeta registerMeta = commandManager.metaBuilder("register")
                .plugin(this)
                .aliases(config.registerAliases().toArray(new String[0]))
                .build();
        commandManager.register(registerMeta, new RegisterCommand(authManager, messages));

        CommandMeta changePasswordMeta = commandManager.metaBuilder("changepassword")
                .plugin(this)
                .aliases(config.changePasswordAliases().toArray(new String[0]))
                .build();
        commandManager.register(changePasswordMeta, new ChangePasswordCommand(authManager, messages));

        CommandMeta adminMeta = commandManager.metaBuilder("mikuauth")
                .plugin(this)
                .aliases("mauth")
                .build();
        commandManager.register(adminMeta, new AdminCommand(this));

        // 对话框"返回聊天栏"按钮触发的内部命令
        CommandMeta closeMeta = commandManager.metaBuilder("mikuauth-close")
                .plugin(this)
                .build();
        commandManager.register(closeMeta, new CloseDialogCommand(authManager));
    }

    /**
     * 注册 PacketEvents 包监听器（对话框关闭兜底检测）。
     * PacketEvents 可能晚于本插件就绪，失败时延迟重试一次。
     */
    private void registerPacketListener() {
        try {
            packetListenerRegistered = DialogCloseListener.tryRegister(server, authManager);
            if (packetListenerRegistered) {
                logger.debug("[MikuAuth] PacketEvents 监听器已注册");
                return;
            }
            server.getScheduler().buildTask(this, () -> {
                if (packetListenerRegistered) {
                    return;
                }
                try {
                    packetListenerRegistered = DialogCloseListener.tryRegister(server, authManager);
                    if (packetListenerRegistered) {
                        logger.debug("[MikuAuth] PacketEvents 监听器已注册（延迟）");
                    } else {
                        logger.warn("[MikuAuth] PacketEvents 未就绪，对话框关闭兜底检测不可用");
                    }
                } catch (Throwable t) {
                    logger.warn("[MikuAuth] PacketEvents 监听器延迟注册失败: {}", t.getMessage());
                }
            }).delay(Duration.ofSeconds(5)).schedule();
        } catch (Throwable t) {
            // 可选依赖的类链接失败发生在调用处（Error），必须 catch Throwable
            logger.warn("[MikuAuth] PacketEvents 监听器注册失败: {}", t.getMessage());
        }
    }

    // ---------------------------------------------------------------------
    // 重载与关闭
    // ---------------------------------------------------------------------

    /**
     * 重载配置与语言文件。
     *
     * <p>除 config.yml / messages.yml 外，还会同步刷新正版验证服务（验证源开关、
     * 超时与缓存参数）——这些参数在 PremiumService 构造期被快照，不刷新会导致
     * "改了配置却不生效"。
     */
    public void reloadConfig() throws IOException {
        config.load(dataDirectory, logger);
        messages.load(dataDirectory, logger);
        if (premiumService != null) {
            premiumService.reload(config);
        }
    }

    @Subscribe
    public void onProxyShutdown(ProxyShutdownEvent event) {
        if (disabled) {
            return;
        }
        if (authManager != null) {
            authManager.shutdown();
        }
        if (migrator != null) {
            migrator.shutdown();
        }
        if (conflictLog != null) {
            // 排空写盘队列，避免丢掉最后几条冲突记录
            conflictLog.shutdown();
        }
        if (backendKickLog != null) {
            // 同理：排空后端拒绝记录的写盘队列
            backendKickLog.shutdown();
        }
        if (premiumService != null) {
            premiumService.shutdown();
        }
        if (database != null) {
            database.close();
        }
        logger.info("[MikuAuth] 已卸载，数据库连接已关闭");
    }

    // ---------------------------------------------------------------------
    // 供命令类访问
    // ---------------------------------------------------------------------

    public MikuConfig config() {
        return config;
    }

    public MikuMessages messages() {
        return messages;
    }

    public DatabaseManager database() {
        return database;
    }

    public AuthManager authManager() {
        return authManager;
    }

    /** 账号迁移器（供 /mikuauth migrate 使用）。 */
    public AccountMigrator migrator() {
        return migrator;
    }

    /** 审计记录器（管理命令的写操作需要留痕）。 */
    public AuditLogger audit() {
        return auditLogger;
    }

    /** 插件日志（命令层记录被吞掉的异步失败时用）。 */
    public Logger logger() {
        return logger;
    }

    /** 渲染管理命令的多行文本（支持 MiniMessage 与 {占位符}）。 */
    public Component renderAdmin(String raw) {
        return TextUtil.render(raw);
    }
}
