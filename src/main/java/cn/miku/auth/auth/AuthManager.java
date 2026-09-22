package cn.miku.auth.auth;

import cn.miku.auth.bedrock.BedrockDetector;
import cn.miku.auth.audit.AuditAction;
import cn.miku.auth.audit.AuditLogger;
import cn.miku.auth.audit.PremiumConflictLog;
import cn.miku.auth.config.MikuConfig;
import cn.miku.auth.config.MikuMessages;
import cn.miku.auth.database.AuthRepository;
import cn.miku.auth.database.DatabaseManager;
import cn.miku.auth.database.StoredPlayer;
import cn.miku.auth.dialog.DialogService;
import cn.miku.auth.display.DisplayManager;
import cn.miku.auth.premium.PremiumResolution;
import cn.miku.auth.premium.PremiumService;
import cn.miku.auth.security.LoginThrottle;
import cn.miku.auth.security.PasswordHasher;
import cn.miku.auth.security.PasswordPolicy;
import cn.miku.auth.util.UuidUtil;
import at.favre.lib.crypto.bcrypt.BCrypt;
import com.velocitypowered.api.event.connection.DisconnectEvent;
import com.velocitypowered.api.proxy.ConnectionRequestBuilder;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.api.proxy.server.RegisteredServer;
import net.kyori.adventure.text.Component;

import java.time.Duration;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;

/**
 * 认证状态机：管理每个在线玩家的认证流程与决策链。
 *
 * <p>决策链（PreLogin，异步）：
 * <pre>
 * 基岩版昵称 ──────────────────────────────────────→ forceOfflineMode（连接后免密）
 * 已注册正版账号（记录含 premiumUuid）──────────────→ forceOnlineMode（连接后免密 + UUID 校验）
 * 已注册离线账号（有密码）──────────────────────────→ forceOfflineMode
 *     其中"同 IP 会话有效"者在此阶段打标记，连接后免密
 * 无记录（或记录无密码）→ 三源并发正版查询：
 *     任一源确认正版 → forceOnlineMode
 *     明确离线       → forceOfflineMode
 *     全部失败       → fail-closed 配置决定拒绝或离线
 * </pre>
 *
 * <p><b>调度模型</b>：正版 / 基岩 / 会话免密这三类玩家在初始调度阶段
 * 即直接进入目标服（不经认证服）；只有<b>需要密码认证</b>的离线玩家进认证服，
 * 完成登录或注册后再被送走。会话判定之所以放在 PreLogin，是因为
 * 初始调度事件是同步的、无法查库（详见 {@link #decideLoginModeAsync}）。
 *
 * <p><b>暴力破解防护</b>：单次连接的尝试次数由 {@code login.max-tries} 限制，
 * 跨连接的失败次数由 {@link LoginThrottle} 按 IP 与账号双维度累计并临时封禁
 * （{@code security.*} 配置段），两者互补。
 *
 * <p><b>协作模块</b>（本类只做编排，具体策略各自独立、可单独测试）：
 * <ul>
 *   <li>{@link PremiumDecider} —— 正版三源查询、期望 UUID 校验（防昵称抢注）与缓存清理；</li>
 *   <li>{@link TransferCoordinator} —— 目标服解析、延迟转服与滞留重试；</li>
 *   <li>{@link LoginThrottle} —— 跨连接的失败计数与临时封禁；</li>
 *   <li>{@link AuthRepository} —— 账号/会话存储契约（由 {@code DatabaseManager} 实现）。</li>
 * </ul>
 *
 * <p>线程模型：决策与密码哈希全部在专用线程池执行，事件线程零阻塞；
 * 状态表为 {@link ConcurrentHashMap}，无锁竞争热点。
 */
public final class AuthManager {

    // ---------------------------------------------------------------------
    // 类型
    // ---------------------------------------------------------------------

    /** PreLogin 阶段的登录模式决策。 */
    public enum LoginMode {
        PREMIUM,
        OFFLINE,
        BEDROCK,
        DENIED
    }

    /** PreLogin 决策结果。 */
    public record ModeDecision(LoginMode mode, Component denyReason) {

        static ModeDecision of(LoginMode mode) {
            return new ModeDecision(mode, null);
        }

        static ModeDecision premium() {
            return new ModeDecision(LoginMode.PREMIUM, null);
        }

        static ModeDecision denied(Component reason) {
            return new ModeDecision(LoginMode.DENIED, reason);
        }
    }

    /** 在线玩家的认证会话状态。 */
    private static final class AuthSession {
        final String username;
        /** 连接来源 IP：仅用于登录失败计数（会话免密判定已在 PreLogin 阶段完成）。 */
        final String ip;
        final long connectedAt;
        /** 待认证文本键：login / register。 */
        volatile String textKey;
        /** 认证是否已通过。 */
        volatile boolean allowed;
        /** Dialog 对话框是否打开（决定静默）。 */
        volatile boolean dialogOpen;
        /** 密码错误次数。 */
        volatile int loginTries;
        /** 上次"未认证不可用命令"提示时间（节流）。 */
        volatile long lastDenyNoticeAt;
        /** 昵称冲突检测已完成（惰性，首次登录失败后触发）。 */
        volatile boolean conflictChecked;
        /** 检测结果：该昵称当前是否对应一个正版账号（离线账号占用正版昵称）。 */
        volatile boolean premiumConflict;

        AuthSession(String username, String ip) {
            this.username = username;
            this.ip = ip;
            this.connectedAt = System.currentTimeMillis();
        }
    }

    // ---------------------------------------------------------------------
    // 依赖与状态
    // ---------------------------------------------------------------------


    private final ProxyServer server;
    private final Object plugin;
    private final Logger logger;
    private final MikuConfig config;
    private final MikuMessages messages;
    private final AuthRepository database;
    private final DialogService dialogService;
    private final DisplayManager display;
    /** 跨会话失败计数与临时封禁（内存态，见类注释）。 */
    private final LoginThrottle throttle;
    /** 认证后的转服调度（目标服解析、延迟送服、滞留重试）。 */
    private final TransferCoordinator transfer;
    /** 正版判定与身份核实（三源查询、期望 UUID 校验、缓存清理）。 */
    private final PremiumDecider premium;
    /** 登录审计（旁路记录，失败不影响认证流程）。 */
    private final AuditLogger audit;
    /** 正版昵称冲突记录文件（玩家只能看到客户端「无效会话」，这里是唯一的事后线索）。 */
    private final PremiumConflictLog conflictLog;

    /** 在线玩家会话状态。 */
    private final ConcurrentHashMap<UUID, AuthSession> sessions = new ConcurrentHashMap<>();
    /** 本次连接内已完成认证的玩家（防止认证完成后被送出时重复触发认证流程）。 */
    private final java.util.Set<UUID> authenticated = java.util.concurrent.ConcurrentHashMap.newKeySet();
    /**
     * PreLogin 阶段判定"会话免密有效"的昵称 → 判定时间戳。
     *
     * <p>作用：初始调度据此让离线玩家<b>直连目标服</b>（跳过认证服），
     * 连接建立后由 {@link #handleConnected(Player)} 消费（用后即删）。
     * 带时间戳是为了清理未真正建立连接的残留（客户端取消、连接中断等）。
     */
    private final ConcurrentHashMap<String, Long> sessionVerifiedNames = new ConcurrentHashMap<>();
    /** 未认证命令提示节流（毫秒）。 */
    private static final long DENY_NOTICE_THROTTLE_MILLIS = 3000;
    /** BCrypt 计算线程数：cost=10 时单次约 60~100ms，2 线程已可满足常规规模。 */
    private static final int CRYPTO_THREADS = 2;
    /** BCrypt 任务队列上限：超出即拒绝，避免洪泛时无界排队吃光内存。 */
    private static final int CRYPTO_QUEUE_CAPACITY = 64;
    /** 同一 IP 提交密码校验的最小间隔（毫秒）：抵抗单 IP 的哈希洪泛。 */
    private static final long IP_CRYPTO_THROTTLE_MILLIS = 400;
    /** IP 节流表的清理阈值与保留时长。 */
    private static final int IP_THROTTLE_MAX_ENTRIES = 4096;
    private static final long IP_THROTTLE_RETAIN_MILLIS = 60_000L;
    /** 昵称 → 最近一次 PreLogin 决策（断线原因分析用）。 */
    private final ConcurrentHashMap<String, ModeRecord> lastLoginModes = new ConcurrentHashMap<>();
    /** 密码哈希/校验线程池：BCrypt 计算较重，绝不阻塞事件线程；队列有界，洪泛时快速失败。 */
    private final ExecutorService cryptoExecutor;
    /** 正在执行密码校验的账号（归一化昵称）：同一账号并发提交只放行一次。 */
    private final java.util.Set<String> cryptoInFlight = java.util.concurrent.ConcurrentHashMap.newKeySet();
    /** IP → 最近一次提交密码校验的时间戳（节流表，按时间自动过期）。 */
    private final ConcurrentHashMap<String, Long> ipCryptoThrottle = new ConcurrentHashMap<>();

    public AuthManager(Object plugin, ProxyServer server, Logger logger, MikuConfig config, MikuMessages messages,
                       AuthRepository database, PremiumService premiumService,
                       DialogService dialogService, DisplayManager display,
                       AuditLogger audit, PremiumConflictLog conflictLog) {
        this.plugin = plugin;
        this.server = server;
        this.logger = logger;
        this.config = config;
        this.messages = messages;
        this.database = database;
        this.premium = new PremiumDecider(premiumService, config, messages, logger);
        this.audit = audit;
        this.conflictLog = conflictLog;
        this.dialogService = dialogService;
        this.display = display;
        this.throttle = new LoginThrottle(config, logger);
        this.transfer = new TransferCoordinator(server, plugin, config, logger);
        this.cryptoExecutor = new ThreadPoolExecutor(
                CRYPTO_THREADS, CRYPTO_THREADS,
                30L, TimeUnit.SECONDS,
                new LinkedBlockingQueue<>(CRYPTO_QUEUE_CAPACITY),
                runnable -> {
                    Thread thread = new Thread(runnable, "MikuAuth-Crypto");
                    thread.setDaemon(true);
                    return thread;
                },
                new ThreadPoolExecutor.AbortPolicy());
    }

    // ---------------------------------------------------------------------
    // PreLogin 决策（异步）
    // ---------------------------------------------------------------------

    /**
     * 决定连接的登录模式。PreLoginEvent 的 EventTask 完成后设置结果。
     * 每次决策都会记录到 {@link #lastLoginModes}，供断线原因分析使用。
     *
     * <p><b>会话免密在决策阶段一并判定</b>：离线玩家若持有有效的同 IP 会话，
     * 会在此处打上标记（{@link #sessionVerifiedNames}），初始调度即可直连目标服，
     * 不必"先进认证服再被送走"——少一次跳服，也避免转服失败滞留。
     *
     * <p><b>异常兜底</b>：本方法返回的 future 必须"总会完成"。数据层异常若向上抛出，
     * PreLogin 的 EventTask 将永不 resume，玩家连接会静默卡死在登录阶段，
     * 因此这里统一把失败降级为明确的拒绝（fail-closed）。
     *
     * @param ip 本次连接的来源 IP（用于会话比对；为 null 时跳过会话判定）
     */
    public CompletableFuture<ModeDecision> decideLoginModeAsync(String username, String ip) {
        purgeStaleExpectations();
        // 1) 基岩版昵称检测（Floodgate 在加密握手阶段已注册玩家）
        if (config.bedrockAutoLogin()
                && BedrockDetector.isBedrockUsername(username, config.bedrockPrefix(), logger)) {
            recordBedrockDecision(username);
            return CompletableFuture.completedFuture(ModeDecision.of(LoginMode.BEDROCK));
        }

        // 2) 查询数据库中已注册账号
        return withFallback(database.findPlayer(username).thenCompose(existing -> {
            StoredPlayer player = existing.orElse(null);
            if (player != null && player.hasPassword()) {
                // 已注册账号：按注册类型锁定模式，防止昵称抢注
                if (player.isPremiumType()) {
                    // 正版账号的身份键就是 Mojang UUID，直接作为期望值（防昵称抢注）
                    UUID expected = player.premiumUuid();
                    if (expected != null) {
                        premium.expect(username, expected);
                        return CompletableFuture.completedFuture(ModeDecision.of(LoginMode.PREMIUM));
                    }
                }
                // 离线账号：顺带判定会话免密（有效则标记，供初始调度直连目标服）
                return resolveOfflineDecisionAsync(username, ip);
            }
            // 未注册 / 已删除密码 → 正版查询
            return decideForUnknownAsync(username);
        }).thenApply(decision -> {
            recordLoginMode(username, decision.mode());
            return decision;
        }), ModeDecision.denied(messages.component("kick.auth-error")), "登录模式决策");
    }

    /**
     * 已注册离线账号的决策：会话有效则标记免密，否则要求密码登录。
     *
     * <p>会话免密原本在认证服内判定（玩家已在 limbo 再被送走），现在提前到这里，
     * 让初始调度直接跳过 limbo。
     */
    private CompletableFuture<ModeDecision> resolveOfflineDecisionAsync(String username, String ip) {
        if (!config.sessionEnabled() || ip == null || ip.isEmpty()) {
            return CompletableFuture.completedFuture(ModeDecision.of(LoginMode.OFFLINE));
        }
        return withFallback(database.findSession(username).thenApply(session -> {
            if (session.isPresent() && ip.equals(session.get().ip())) {
                sessionVerifiedNames.put(MikuConfig.normalize(username), System.currentTimeMillis());
                logger.debug("[调度] {} 的会话有效（IP 一致），本次直连目标服", username);
            }
            return ModeDecision.of(LoginMode.OFFLINE);
        }), ModeDecision.of(LoginMode.OFFLINE), "会话免密判定");
    }

    /** 该昵称本次连接是否已通过会话免密判定（初始调度用）。 */
    public boolean isSessionVerifiedFor(String username) {
        return sessionVerifiedNames.containsKey(MikuConfig.normalize(username));
    }

    private void recordLoginMode(String username, LoginMode mode) {
        lastLoginModes.put(MikuConfig.normalize(username),
                new ModeRecord(mode, System.currentTimeMillis()));
    }

    /**
     * 记录基岩版决策：同时覆盖<b>带前缀</b>与<b>无前缀</b>两种昵称形态。
     *
     * <p>PreLogin 阶段的昵称与连接后的最终昵称可能相差一个 Floodgate 前缀
     * （如 "junxiesky" vs ".junxiesky"）——若只记录单一形态，
     * 认证/调度阶段将查询不到决策，导致基岩玩家被误按离线处理并误入 limbo。
     */
    private void recordBedrockDecision(String username) {
        String live = BedrockDetector.getLivePrefix(config.bedrockPrefix(), logger);
        String stripped = username.startsWith(live)
                ? username.substring(live.length())
                : username;
        recordLoginMode(username, LoginMode.BEDROCK);
        recordLoginMode(stripped, LoginMode.BEDROCK);
        if (!live.isEmpty()) {
            recordLoginMode(live + stripped, LoginMode.BEDROCK);
        }
    }

    /** 读取昵称最近一次 PreLogin 决策（初始调度用）；无记录返回 null。 */
    public LoginMode lastLoginModeFor(String username) {
        ModeRecord record = lastLoginModes.get(MikuConfig.normalize(username));
        return record != null ? record.mode() : null;
    }

    /**
     * 登录阶段断开的原因分析：结合最近的 PreLogin 决策与断开状态，
     * 在日志中给出"玩家为什么进不来"的判断（重点：正版会话校验失败、同名冲突）。
     */
    public void logJoinFailure(String username, DisconnectEvent.LoginStatus status, String ip) {
        ModeRecord record = lastLoginModes.get(MikuConfig.normalize(username));
        if (record == null || record.mode() == LoginMode.BEDROCK) {
            return;
        }
        if (record.mode() == LoginMode.PREMIUM) {
            // 强制正版校验的昵称：盗版客户端的失败发生在代理内部（无自定义消息），
            // 这里依据决策记录给出最可能的原因
            logger.warn("[进服诊断] {} 未能进入（状态: {}）：该昵称已确认为正版，连接被强制正版会话校验，"
                            + "使用离线/盗版客户端者只会看到客户端原生的\"无效会话\"错误"
                            + "（该提示由客户端在加密握手阶段自行产生，玩家尚未进入任何服务器，"
                            + "插件无法投递自定义消息——这是 Minecraft 协议的限制）。"
                            + "处理方式取决于该昵称是否仍属于某个正版账号："
                            + "① 仍有效 → 让玩家改用正版启动器登录，或改用其他昵称；"
                            + "② 已失效（玩家在 Mojang 改名后遗留、记录过期）→ 才可执行 /mikuauth unbind {} 清除绑定。"
                            + "切勿对\"仍有正版账号持有\"的昵称执行 unbind——那会让任何离线客户端都能占用它。"
                            + "先执行 /mikuauth diagnose {} 查看三源结论与库中记录再决定。",
                    username, describeStatus(status), username, username);
            // ★ 单独落盘：玩家只能看到客户端的「无效会话」，这里是事后唯一能查到的线索
            conflictLog.record(username, ip, describeStatus(status),
                    "该昵称已确认为正版（与正版账号 ID 冲突）；详情: /mikuauth diagnose " + username);
            return;
        }
        if (record.mode() == LoginMode.DENIED) {
            logger.info("[进服诊断] {} 未能进入（状态: {}）：连接被本插件拒绝（fail-closed 或冲突策略）。", username, describeStatus(status));
            return;
        }
        if (status == DisconnectEvent.LoginStatus.CONFLICTING_LOGIN) {
            logger.warn("[进服诊断] {} 未能进入：同名玩家已在线（重复登录冲突）。", username);
        }
    }

    private static String describeStatus(DisconnectEvent.LoginStatus status) {
        return switch (status) {
            case SUCCESSFUL_LOGIN -> "已进入";
            case CONFLICTING_LOGIN -> "同名冲突";
            case CANCELLED_BY_PROXY -> "被代理取消";
            case CANCELLED_BY_USER -> "玩家取消";
            case CANCELLED_BY_USER_BEFORE_COMPLETE -> "玩家在完成前取消";
            case PRE_SERVER_JOIN -> "进入服务器前断开";
        };
    }

    /** 昵称最近一次 PreLogin 决策（断线原因分析用）。 */
    private record ModeRecord(LoginMode mode, long createdAt) {
    }

    // ---------------------------------------------------------------------
    // 进服诊断：判定链路回放（/mikuauth diagnose）
    // ---------------------------------------------------------------------

    /** 诊断报告：数据库状态 / 正版查询 / 决策 / 冲突说明（各段已本地化，null = 无该段）。 */
    public record DiagnoseReport(String dbLine, String apiLine, String decisionLine, String conflictLine) {
    }

    /**
     * 回放指定昵称会得到的进服判定链路，帮助管理员理解"玩家为什么进不来"。
     * 重点覆盖：与正版玩家 ID 冲突（昵称被另一侧占用）的场景。
     */
    public CompletableFuture<DiagnoseReport> diagnoseAsync(String nickname) {
        String player = nickname;
        return database.findPlayer(nickname).thenCompose(existing ->
                premium.available()
                        ? premium.resolveAsync(nickname).thenApply(res -> buildReport(player, existing.orElse(null), res))
                        : CompletableFuture.completedFuture(
                        buildReport(player, existing.orElse(null), null)));
    }

    private DiagnoseReport buildReport(String nickname, StoredPlayer stored, PremiumResolution api) {
        String dbLine;
        if (stored == null) {
            dbLine = messages.raw("admin.diagnose.db-none");
        } else if (stored.isPremiumType()) {
            dbLine = messages.raw("admin.diagnose.db-premium")
                    .replace("{uuid}", stored.premiumUuid() == null ? "-" : stored.premiumUuid().toString());
        } else if (stored.hasPassword()) {
            dbLine = messages.raw("admin.diagnose.db-offline");
        } else {
            dbLine = messages.raw("admin.diagnose.db-offline-no-password");
        }

        String apiLine;
        if (api == null) {
            apiLine = messages.raw("admin.diagnose.api-disabled");
        } else if (api.isPremium()) {
            apiLine = messages.raw("admin.diagnose.api-premium")
                    .replace("{source}", api.source());
        } else if (api.isOffline()) {
            apiLine = messages.raw("admin.diagnose.api-offline");
        } else {
            apiLine = messages.raw("admin.diagnose.api-unknown");
        }

        String conflictLine = null;
        String decisionLine;
        if (stored != null && stored.hasPassword() && stored.isPremiumType()) {
            decisionLine = messages.raw("admin.diagnose.decision-online");
        } else if (stored != null && stored.hasPassword()) {
            decisionLine = messages.raw("admin.diagnose.decision-offline");
            if (api != null && api.isPremium()) {
                conflictLine = messages.raw("admin.diagnose.conflict")
                        .replace("{player}", nickname);
            }
        } else if (api == null) {
            decisionLine = messages.raw("admin.diagnose.decision-offline");
        } else if (api.isPremium()) {
            decisionLine = messages.raw("admin.diagnose.decision-online");
        } else if (api.isOffline()) {
            decisionLine = messages.raw("admin.diagnose.decision-offline");
        } else {
            decisionLine = config.premiumFailClosed()
                    ? messages.raw("admin.diagnose.decision-deny")
                    : messages.raw("admin.diagnose.decision-offline");
        }
        return new DiagnoseReport(dbLine, apiLine, decisionLine, conflictLine);
    }

    /** 未注册昵称的正版判定。 */
    private CompletableFuture<ModeDecision> decideForUnknownAsync(String username) {
        if (!premium.available()) {
            return CompletableFuture.completedFuture(ModeDecision.of(LoginMode.OFFLINE));
        }
        return premium.resolveAsync(username).thenCompose(resolution -> {
            if (!config.autoMigrateRenamed()) {
                return CompletableFuture.completedFuture(applyResolution(username, resolution));
            }
            // 确认为正版：若该 Mojang UUID 在库中已有账号（只是昵称不同）→ 玩家改名了，
            // 把账号数据迁到新昵称，旧昵称随之释放（而不是又登记一条新记录留下旧 ID）
            if (resolution.isPremium()) {
                return migrateRenamedAccountAsync(username, resolution.uuid())
                        .thenApply(ignored -> applyResolution(username, resolution));
            }
            // 权威源判定该昵称已不存在：库里若还留着"正版"记录，那就是改名遗留的死昵称
            if (resolution.isOffline()) {
                return releaseStaleAccountAsync(username, null)
                        .thenApply(released -> applyResolution(username, resolution));
            }
            // 冲突（权威源=离线、镜像=正版）：用库中记录判断是历史映射还是抢注。
            // 镜像给出的 UUID 与库中该昵称记录一致 → 是号主改名留下的历史记录，清理并放行；
            // 不一致（或库里根本没记录）→ 维持保守策略，交给 applyResolution 判定。
            if (resolution.hasHistoricalUuid()) {
                return releaseStaleAccountAsync(username, resolution.uuid())
                        .thenApply(released -> released
                                ? ModeDecision.of(LoginMode.OFFLINE)
                                : applyResolution(username, resolution));
            }
            return CompletableFuture.completedFuture(applyResolution(username, resolution));
        });
    }

    /**
     * 正版玩家改名后的自动迁移。
     *
     * <p>触发时机：某昵称在库中查不到账号，但正版查询确认它属于 UUID U，
     * 而 U 在库中<b>已有</b>账号（说明玩家只是改了名）。此时把那条账号迁到新昵称 ——
     * 密码、注册信息、登录统计全部保留，旧昵称从唯一索引中消失即被释放。
     *
     * <p>没有这一步，旧逻辑会在新昵称下再登记一条记录，旧昵称的旧记录就永久留了下来。
     */
    private CompletableFuture<Void> migrateRenamedAccountAsync(String newName, UUID uuid) {
        if (uuid == null) {
            return CompletableFuture.completedFuture(null);
        }
        return withFallback(database.findPlayerByUuid(uuid).thenCompose(existing -> {
            if (existing.isEmpty()) {
                return CompletableFuture.completedFuture(null);
            }
            StoredPlayer old = existing.get();
            if (old.nicknameLower().equals(MikuConfig.normalize(newName))) {
                return CompletableFuture.completedFuture(null); // 昵称一致，无需迁移
            }
            return database.renameAccount(uuid, newName).thenAccept(migrated -> {
                if (Boolean.TRUE.equals(migrated)) {
                    logger.info("[改名迁移] 正版玩家改名：{} → {}（UUID {}），"
                                    + "账号数据已迁移到新昵称，旧昵称已释放",
                            old.nickname(), newName, uuid);
                } else {
                    logger.warn("[改名迁移] {} → {}（UUID {}）未能迁移：新昵称已被其他账号占用",
                            old.nickname(), newName, uuid);
                }
            });
        }), null, "改名迁移");
    }

    /**
     * 清理陈旧的正版记录，释放被它占用的昵称（"防止死昵称"）。
     *
     * <p>触发条件（调用方已判定）：该昵称已不再属于记录里的正版 UUID。
     * 常见成因是玩家在 Mojang 改名后，旧昵称既不在 Mojang 名下、又被库里的旧记录
     * 标记为正版 —— 结果谁都进不来（强制正版会话校验必然失败），成了"死昵称"。
     *
     * <p>只清理没有密码的记录，避免误删仍可登录的凭据（见
     * {@link DatabaseManager#releaseStaleAccount}）。
     *
     * @param historicalUuid 镜像给出的历史 UUID；为 null 时只按"正版 + 无密码"匹配
     */
    private CompletableFuture<Boolean> releaseStaleAccountAsync(String nickname, UUID historicalUuid) {
        return withFallback(database.releaseStaleAccount(nickname, historicalUuid).thenApply(released -> {
            if (released) {
                logger.warn("[死昵称清理] {} 的记录仍标记为正版（UUID {}），但该昵称已不属于它"
                                + "（玩家在 Mojang 改名）→ 已清理陈旧记录并释放昵称",
                        nickname, historicalUuid == null ? "未知" : historicalUuid);
            }
            return released;
        }), false, "死昵称清理");
    }

    private ModeDecision applyResolution(String username, PremiumResolution resolution) {
        if (resolution.isPremium()) {
            premium.expect(username, resolution.uuid());
            return ModeDecision.premium();
        }
        if (resolution.isOffline()) {
            return ModeDecision.of(LoginMode.OFFLINE);
        }
        // 全部验证源失败
        if (config.premiumFailClosed()) {
            logger.warn("[正版验证] " + username + " 无法验证（所有验证源失败），已拒绝连接（fail-closed）");
            audit.record(AuditAction.REJECT_PREMIUM_FAILED, username, null, null,
                    "所有正版验证源失败，按 fail-closed 拒绝");
            return ModeDecision.denied(messages.component("kick.premium-verify-failed"));
        }
        logger.warn("[正版验证] " + username + " 无法验证，按离线处理（fail-closed 已关闭）");
        return ModeDecision.of(LoginMode.OFFLINE);
    }

    // ---------------------------------------------------------------------
    // GameProfileRequest：正版 UUID 校验（防昵称抢注）
    // ---------------------------------------------------------------------

    /**
     * 校验正版连接的实际 UUID 与 PreLogin 决策时记录的 UUID 是否一致
     * （委托 {@link PremiumDecider#verifyProfile}）。
     *
     * <p>匹配成功时该连接被标记为"已验证正版"（认证流程据此免密）；
     * 不匹配即视为抢注攻击，返回拒绝原因。非正版决策连接直接放行。
     */
    public Component verifyPremiumProfile(String username, UUID actualUuid) {
        Component deny = premium.verifyProfile(username, actualUuid);
        if (deny != null) {
            audit.record(AuditAction.REJECT_NAME_SNIPE, username, actualUuid, null,
                    "实际 UUID 与 PreLogin 登记的正版 UUID 不一致");
        }
        return deny;
    }

    /** 清理超过 60 秒未消费的 PreLogin 缓存条目（连接中断等残留）。 */
    private void purgeStaleExpectations() {
        // 正版判定器的两张缓存由它自己按阈值清理
        premium.purgeStale();
        if (lastLoginModes.size() < 64 && sessionVerifiedNames.size() < 64) {
            return;
        }
        long cutoff = System.currentTimeMillis() - 60_000L;
        lastLoginModes.values().removeIf(record -> record.createdAt() < cutoff);
        // 会话免密标记未被消费（客户端取消/连接中断）时在此过期，避免残留
        sessionVerifiedNames.values().removeIf(markedAt -> markedAt < cutoff);
    }

    // ---------------------------------------------------------------------
    // 玩家到达（认证服或免密直连的目标服）
    // ---------------------------------------------------------------------

    /**
     * 玩家连接后的入口：判定免密路径或启动登录/注册流程。
     *
     * <p><b>调度模型</b>（参考 LibreLogin/VeloAuth）：只有<b>需要密码认证的离线玩家</b>
     * 进入 limbo 完成注册/登录；正版、基岩与会话免密玩家由 PreLogin 决策直接调度到
     * 目标服（免密，无需认证），在本方法中完成登记与提示。
     */
    public void handleConnected(Player player) {
        handleConnected(player, null);
    }

    /**
     * 玩家连接后的入口，带"刚连上哪台服务器"。
     *
     * <p><b>为什么必须传 connectedServer</b>：判断"玩家在不在认证服"<b>不能</b>用
     * {@code player.getCurrentServer()} —— 在 {@code ServerConnectedEvent} 这一刻，
     * 该连接还没写回 player 的当前服务器（VelocityCTD 实测：事件里读到的是空的）。
     * 于是一个正常落在认证服的离线玩家会被误判成"停留在正式服"，紧接着插件会把他
     * "送回"他已经在的那台认证服 —— Velocity 以 ALREADY_CONNECTED 拒绝，而这个失败又被
     * 当成"认证服不可用"，玩家直接被踢下线。表现为：<b>离线玩家永远无法注册/登录</b>。
     * 正版/基岩/会话免密玩家在第 1~3 步就返回了，所以这个坑只在离线认证路径上暴露。
     *
     * <p>{@code ServerConnectedEvent.getServer()} 才是这一刻的权威答案。
     *
     * @param connectedServer 刚连上的服务器名；null = 未知，回退到实时查询
     */
    public void handleConnected(Player player, String connectedServer) {
        // 同一次连接内已认证完成（如免密直连后触发的目标服连接事件）：
        // 不再重复启动流程；断线重连时 authenticated 会被清除，重新判定
        if (authenticated.contains(player.getUniqueId())) {
            logger.debug("[认证] {} 已在本连接内完成认证，跳过重复处理", player.getUsername());
            return;
        }
        String ip = player.getRemoteAddress().getAddress().getHostAddress();
        AuthSession session = new AuthSession(player.getUsername(), ip);
        sessions.put(player.getUniqueId(), session);

        LoginMode mode = lastLoginModeFor(player.getUsername());
        logger.debug("[认证] {} 验证路径: {}", player.getUsername(),
                mode != null ? mode : "未知（按离线处理）");

        // 1) 会话免密直连：PreLogin 阶段已判定同 IP 会话有效，初始调度直接跳过认证服，
        //    因此这里无需再查库，消费标记即可放行（用后即删）
        if (sessionVerifiedNames.remove(MikuConfig.normalize(player.getUsername())) != null) {
            logger.info("[会话免密] {} 的会话有效（PreLogin 已判定），免密直连目标服", player.getUsername());
            renewSessionIfEnabled(player, session);
            completeAuth(player, session, "auth.auto.session", false);
            return;
        }
        // 2) 正版免密：PreLogin 决策为正版，代理已强制会话校验并通过
        //    （verifyPremiumProfile 在 GameProfileRequest 阶段核对了实际 UUID）
        if (mode == LoginMode.PREMIUM
                && premium.isVerified(player.getUniqueId())) {
            logger.debug("[认证] {} 正版免密通过", player.getUsername());
            completeAuth(player, session, "auth.auto.premium", false);
            // 正版玩家自动登记（无密码），下次 PreLogin 可直接 forceOnlineMode
            withFallback(database.findPlayer(player.getUsername()).thenAccept(existing -> {
                if (existing.isEmpty()) {
                    database.register(player.getUniqueId(), player.getUsername(), null,
                            StoredPlayer.TYPE_PREMIUM, ip);
                }
            }), null, "正版玩家自动登记");
            return;
        }
        // 3) 基岩免密：Floodgate 已完成身份验证
        //    ★ 基岩版玩家不写库、不要求密码——这是刻意的：Floodgate 在加密握手阶段
        //      就以 XUID 完成了身份绑定，服务端没有可被冒用的"昵称"概念，
        //      因此这里既不需要登记账号，也不需要纳入 IP 配额（与正版账号同理）。
        //      副作用：/mikuauth accounts 查不到基岩版玩家，属预期行为。
        if (config.bedrockAutoLogin()
                && (mode == LoginMode.BEDROCK || BedrockDetector.isBedrockPlayer(player.getUniqueId()))) {
            logger.debug("[认证] {} 基岩版免密通过", player.getUsername());
            completeAuth(player, session, "auth.auto.bedrock", false);
            return;
        }
        // 4) 需要密码认证：必须位于认证服（隔离边界），否则先送回认证服
        String currentServer = resolveCurrentServer(player, connectedServer);
        if (!isAuthServerName(currentServer)) {
            logger.warn("[调度] {} 需要在认证服 '{}' 完成认证，但当前位于 '{}'，已送回认证服",
                    player.getUsername(), config.authServer(),
                    currentServer == null ? "未知" : currentServer);
            sendToAuthServer(player, session, currentServer);
            return;
        }
        // 5) 已注册登录 / 新玩家注册（会话免密已在第 1 步处理）
        startAuthFlow(player, session);
    }

    /** 进入登录/注册流程：查库决定弹登录框还是注册框。 */
    private void startAuthFlow(Player player, AuthSession session) {
        withFallback(database.findPlayer(player.getUsername()).thenAccept(existing -> {
            StoredPlayer stored = existing.orElse(null);
            if (stored == null || !stored.hasPassword()) {
                // 无密码记录（正版登记或已删除密码）→ 视为未注册
                logger.debug("[认证] {} 未注册，进入注册流程", player.getUsername());
                startPending(player, session, "register");
                return;
            }
            startPending(player, session, "login");
        }), null, "玩家记录查询");
    }

    /** 取玩家当前所在服务器：优先用事件给出的落点，其次才读实时状态。 */
    private String resolveCurrentServer(Player player, String connectedServer) {
        if (connectedServer != null && !connectedServer.isEmpty()) {
            return connectedServer;
        }
        return liveServerName(player);
    }

    /** 实时查询玩家所在服务器名；查不到返回 null。 */
    private static String liveServerName(Player player) {
        return player.getCurrentServer().map(conn -> conn.getServerInfo().getName()).orElse(null);
    }

    /** 该名字是否就是配置里的认证服（大小写不敏感）。 */
    private boolean isAuthServerName(String serverName) {
        return serverName != null && serverName.equalsIgnoreCase(config.authServer());
    }

    /**
     * 把玩家送回认证服（未认证玩家绝不能停留在正式服）。
     *
     * <p>送服前会再核对一次"是不是已经就在认证服上"：若已在那台服上，<b>绝不能</b>再发连接请求
     * —— Velocity 会以 ALREADY_CONNECTED 拒绝，而这个失败在这里会被当成"认证服不可用"把玩家踢掉。
     * 这种情况直接进入认证流程（玩家本来就该在那台服上认证）。
     */
    private void sendToAuthServer(Player player, AuthSession session, String knownCurrent) {
        String authServer = config.authServer();
        if (isAuthServerName(knownCurrent) || isAuthServerName(liveServerName(player))) {
            logger.warn("[调度] {} 实际已在认证服 '{}' 上，跳过重复送服并直接进入认证流程",
                    player.getUsername(), authServer);
            startAuthFlow(player, session);
            return;
        }
        server.getServer(authServer).ifPresentOrElse(target ->
                        player.createConnectionRequest(target).connect().whenComplete((result, throwable) -> {
                            if (throwable != null || result == null || !result.isSuccessful()) {
                                // 必须把真实原因打出来：缺了它排障只能靠猜（线上踩过）
                                logger.warn("[调度] {} 送回认证服 '{}' 失败（{}），已断开连接",
                                        player.getUsername(), authServer, failureReason(result, throwable));
                                player.disconnect(messages.component("kick.auth-error"));
                            }
                        }),
                () -> logger.error("[调度] 无法送回认证服 '{}'（velocity.toml 的 [servers] 中没有它）", authServer));
    }

    /** 送服失败的原因描述（连接状态或异常），仅用于日志排障。 */
    private static String failureReason(ConnectionRequestBuilder.Result result, Throwable throwable) {
        if (throwable != null) {
            String message = throwable.getMessage();
            return throwable.getClass().getSimpleName() + (message == null ? "" : ": " + message);
        }
        if (result == null) {
            return "连接请求未返回结果";
        }
        return String.valueOf(result.getStatus());
    }

    /**
     * 会话免密进入时续期（滑动窗口）。
     *
     * <p>由 {@code session.renew-on-session-login} 控制：开启后，玩家在有效期内从同一 IP
     * 进入即顺延一个完整时长——活跃玩家（例如天天上线）无需反复输密码；关闭则保持
     * "从上次密码登录起硬性到期"的旧行为。
     *
     * <p>注意：续期意味着"持续活跃 = 持续免密"。若希望免密有硬性上限，
     * 可调小 {@code session.duration-minutes} 或关闭本项。
     */
    private void renewSessionIfEnabled(Player player, AuthSession session) {
        if (!config.sessionEnabled() || !config.sessionRenewOnLogin()) {
            return;
        }
        long expiresAt = System.currentTimeMillis() + config.sessionDurationMinutes() * 60_000L;
        withFallback(database.saveSession(player.getUsername(), session.ip, expiresAt), null, "会话续期");
        logger.debug("[会话免密] {} 的会话已续期至 {} 分钟后",
                player.getUsername(), config.sessionDurationMinutes());
    }

    /** 启动待认证流程：提示 + 尝试 Dialog（延迟发送以避开子服 Join Game 包竞争）。 */
    private void startPending(Player player, AuthSession session, String textKey) {
        // 自愈保护：并发路径（如正版/基岩免密）可能已在窗口内完成认证，
        // 此时会话已被移除，绝不能再弹一次登录框
        if (session.allowed || sessions.get(player.getUniqueId()) != session) {
            return;
        }
        session.textKey = textKey;
        int timeout = config.authTimeoutSeconds();
        display.startTracking(player, textKey, Map.of("player", player.getUsername()), timeout);

        long delayMillis = config.dialogShowDelayMillis();
        if (delayMillis <= 0) {
            tryShowDialog(player, session, textKey);
            return;
        }
        // show_dialog 与子服 Join Game 同时到达时部分客户端会忽略对话框，必须延迟发送
        server.getScheduler()
                .buildTask(plugin, () -> {
                    if (player.isActive() && sessions.containsKey(player.getUniqueId())
                            && !session.allowed && !session.dialogOpen) {
                        tryShowDialog(player, session, textKey);
                    }
                })
                .delay(Duration.ofMillis(delayMillis))
                .schedule();
    }


    /**
     * 立即发送 Dialog；成功后进入静默。对话框正文显示配置的认证时限。
     *
     * @return 是否成功发送
     */
    private boolean tryShowDialog(Player player, AuthSession session, String textKey) {
        String error = textKey.equals("login")
                ? dialogService.showLogin(player, null)
                : dialogService.showRegister(player, null);
        if (error != null) {
            logger.debug("[对话框] " + player.getUsername() + " 无法使用 Dialog: " + error);
            // 无法使用 Dialog → 恢复聊天栏/Title/BossBar 提示
            display.exitSilent(player);
            display.chat(player, textKey + ".chat-usage", Map.of());
            return false;
        }
        logger.debug("[对话框] 已向 " + player.getUsername() + " 发送"
                + (textKey.equals("login") ? "登录" : "注册") + "对话框（等待提交）");
        session.dialogOpen = true;
        display.enterSilent(player);
        return true;
    }

    // ---------------------------------------------------------------------
    // 命令处理：/login 与 /register（Dialog 提交与聊天栏共用）
    // ---------------------------------------------------------------------

    /**
     * 确保待认证玩家持有认证会话（自愈）。
     * 玩家在认证服内但会话缺失时：<b>强制清除已认证残留标记并重建认证流程</b>——
     * 无论此前因何种原因（转服失败滞留、数据被重置、状态残留）导致会话丢失，
     * 玩家都必须能够重新进入注册/登录流程。不在认证服的玩家返回 null。
     */
    private AuthSession ensureSession(Player player) {
        AuthSession session = sessions.get(player.getUniqueId());
        if (session != null) {
            return session;
        }
        if (!transfer.isOnAuthServer(player)) {
            return null;
        }
        logger.debug("[认证] {} 位于认证服但缺少认证会话，重建认证流程（自愈）", player.getUsername());
        // 清除可能存在的"已认证"残留标记：它会让 handleConnected 静默短路，
        // 导致玩家永远无法重新进入注册/登录流程
        authenticated.remove(player.getUniqueId());
        premium.revokeVerified(player.getUniqueId());
        handleConnected(player);
        return sessions.get(player.getUniqueId());
    }

    public void handleLoginCommand(Player player, String password) {
        AuthSession session = ensureSession(player);
        if (session == null || session.allowed) {
            display.chatAlways(player, "error.already-authed",
                    Map.of("duration", String.valueOf(config.sessionDurationMinutes())));
            return;
        }
        if (!"login".equals(session.textKey)) {
            display.chatAlways(player, "error.please-register", Map.of());
            return;
        }
        // 跨会话封禁检查：本 IP 或本账号近期失败过多，直接拒绝（不再消耗 BCrypt）
        LoginThrottle.Lock lock = throttle.check(session.ip, session.username);
        if (lock != null) {
            display.chatAlways(player, "error.locked",
                    Map.of("minutes", String.valueOf(lock.remainingMinutes())));
            return;
        }
        // 命令执行即离开对话框（提交后客户端已关闭对话框）：这里只改会话标记，
        // DisplayManager 的静默由"重开对话框"或 completeAuth 的 stopTracking 收尾
        session.dialogOpen = false;
        if (password == null || password.isEmpty()) {
            failLogin(player, session, "error.password-empty", Map.of(), false);
            return;
        }
        // 准入控制：同 IP 提交过快或同账号并发提交一律拒绝，防止 BCrypt 洪泛
        if (!tryAcquireCryptoSlot(session.username, session.ip)) {
            display.chat(player, "error.too-fast", Map.of());
            return;
        }
        database.findPlayer(player.getUsername()).thenAccept(existing -> {
            StoredPlayer stored = existing.orElse(null);
            if (stored == null || !stored.hasPassword()) {
                releaseCryptoSlot(session.username);
                failLogin(player, session, "error.not-registered", Map.of(), true);
                return;
            }
            try {
                cryptoExecutor.execute(() -> verifyPassword(player, session, password, stored));
            } catch (RejectedExecutionException e) {
                releaseCryptoSlot(session.username);
                logger.warn("[登录] 密码校验队列已满，拒绝 {} 的请求", player.getUsername());
                display.chatAlways(player, "error.server-busy", Map.of());
            }
        }).exceptionally(throwable -> {
            logger.error("[MikuAuth] 登录密码查询异常: {}", throwable.toString());
            releaseCryptoSlot(session.username);
            display.chatAlways(player, "error.server-busy", Map.of());
            return null;
        });
    }

    /** 在线程池内执行密码校验；无论结果如何都会释放准入名额。 */
    private void verifyPassword(Player player, AuthSession session, String password, StoredPlayer stored) {
        try {
            boolean verified;
            try {
                // 支持迁移来的历史哈希（AuthMe 的 $SHA$/$SHA512$/MD5 等），
                // 由 PasswordHasher 按格式自动识别
                verified = PasswordHasher.verify(password, stored.passwordHash());
            } catch (RuntimeException e) {
                logger.warn("[登录] 密码校验异常: {}", e.getMessage());
                verified = false;
            }
            if (verified) {
                // 旧算法（非 BCrypt）在首次成功登录时就地升级为当前标准，
                // 玩家无感，但哈希强度随活跃度逐步提升
                upgradeHashIfNeeded(player, stored, password);
                completeAuth(player, session, "auth.success.login", true);
                return;
            }
            session.loginTries++;
            checkNicknameConflictAsync(player, session);
            // 跨会话计数：即使玩家断线重连，失败次数依然累计
            LoginThrottle.Lock lock = throttle.recordFailure(session.ip, session.username);
            int max = config.maxLoginTries();
            audit.record(AuditAction.LOGIN_FAIL, session.username, player.getUniqueId(), session.ip,
                    "密码错误（本次连接第 " + session.loginTries + " 次）"
                            + (lock != null ? "，已触发临时封禁" : ""));
            if (max > 0 && session.loginTries >= max) {
                kick(player, "kick.too-many-tries", session);
                return;
            }
            int remaining = max > 0 ? max - session.loginTries : -1;
            Map<String, String> placeholders = lock != null
                    ? Map.of("remaining", String.valueOf(Math.max(0, remaining)),
                             "minutes", String.valueOf(lock.remainingMinutes()))
                    : remaining >= 0 ? Map.of("remaining", String.valueOf(remaining)) : Map.of();
            failLogin(player, session, lock != null ? "error.password-wrong-locked" : "error.password-wrong",
                    placeholders, true);
        } finally {
            releaseCryptoSlot(session.username);
        }
    }

    /**
     * 如果存储的是迁移来的旧算法哈希，成功校验后就地重写为 BCrypt。
     *
     * <p>失败只记 WARN：升级是锦上添花，不能影响本次登录成功的结果。
     */
    private void upgradeHashIfNeeded(Player player, StoredPlayer stored, String password) {
        if (!PasswordHasher.needsUpgrade(stored.passwordHash())) {
            return;
        }
        String upgraded;
        try {
            upgraded = PasswordHasher.hash(password, config.bcryptCost());
        } catch (RuntimeException e) {
            logger.warn("[登录] 生成新哈希失败: {}", e.getMessage());
            return;
        }
        database.updatePassword(stored.nickname(), upgraded).whenComplete((updated, error) -> {
            if (error != null) {
                logger.warn("[登录] {} 的密码哈希升级失败: {}", stored.nickname(), error.toString());
            } else if (Boolean.TRUE.equals(updated)) {
                logger.info("[登录] {} 的密码哈希已从旧算法升级为 BCrypt（迁移账号首次登录）",
                        stored.nickname());
            }
        });
    }

    /**
     * 登录失败后惰性检测昵称冲突：该昵称当前是否对应一个正版账号。
     * 命中时（离线账号占用正版昵称），后续错误提示会附带冲突说明，
     * 帮助正版玩家理解"输入密码错误"的真实原因。
     * 结果缓存在会话内（缓存命中时近乎零开销）。
     */
    private void checkNicknameConflictAsync(Player player, AuthSession session) {
        if (session.conflictChecked) {
            return;
        }
        session.conflictChecked = true;
        premium.resolveAsync(session.username).thenAccept(resolution ->
                session.premiumConflict = resolution.isPremium());
    }

    /** 是否存在"昵称被正版账号占用"的冲突（已检测且命中）。 */
    private boolean hasNicknameConflict(AuthSession session) {
        return session.conflictChecked && session.premiumConflict;
    }

    /**
     * 未认证玩家尝试使用白名单外命令时的反馈（3 秒节流，防止刷屏）。
     */
    public void handleDeniedCommand(Player player) {
        AuthSession session = sessions.get(player.getUniqueId());
        if (session == null) {
            return;
        }
        long now = System.currentTimeMillis();
        if (now - session.lastDenyNoticeAt < DENY_NOTICE_THROTTLE_MILLIS) {
            return;
        }
        session.lastDenyNoticeAt = now;
        display.chatAlways(player, "error.must-authenticate", Map.of());
    }

    public void handleRegisterCommand(Player player, String password, String confirm) {
        AuthSession session = ensureSession(player);
        if (session == null || session.allowed) {
            display.chatAlways(player, "error.already-authed",
                    Map.of("duration", String.valueOf(config.sessionDurationMinutes())));
            return;
        }
        if (!"register".equals(session.textKey)) {
            display.chatAlways(player, "error.please-login", Map.of());
            return;
        }
        session.dialogOpen = false;

        // 基础校验（同步快速路径）：长度/字符集统一走 PasswordPolicy，
        // 与 /changepassword、/mikuauth setpassword 保持同一套规则
        PasswordPolicy.Violation violation = PasswordPolicy.check(config, password);
        if (violation != null) {
            failRegister(player, session, violation.messageKey(), violation.placeholders());
            return;
        }
        if (!password.equals(confirm)) {
            failRegister(player, session, "error.password-mismatch", Map.of());
            return;
        }
        // IP 配额
        int maxAccounts = config.maxAccountsPerIp();
        if (maxAccounts > 0) {
            database.countAccountsByIp(session.ip).thenAccept(count -> {
                if (count >= maxAccounts) {
                    // 拒绝原因是安全事件（同 IP 批量注册），必须落审计便于事后追溯
                    audit.record(AuditAction.REJECT_IP_LIMIT, session.username, player.getUniqueId(),
                            session.ip, "该 IP 名下已有 " + count + " 个离线账号，达到上限 " + maxAccounts);
                    failRegister(player, session, "error.ip-limit", Map.of());
                } else {
                    doRegister(player, session, password);
                }
            }).exceptionally(throwable -> {
                logger.error("[MikuAuth] IP 配额查询异常: {}", throwable.toString());
                failRegister(player, session, "error.server-busy", Map.of());
                return null;
            });
            return;
        }
        doRegister(player, session, password);
    }

    private void doRegister(Player player, AuthSession session, String password) {
        if (!tryAcquireCryptoSlot(session.username, session.ip)) {
            display.chat(player, "error.too-fast", Map.of());
            return;
        }
        try {
            cryptoExecutor.execute(() -> {
                try {
                    String hash = BCrypt.withDefaults()
                            .hashToString(config.bcryptCost(), password.toCharArray());
                    // 离线账号的身份键 = 由昵称推导的离线 UUID（与代理分配给玩家的一致）
                    database.register(UuidUtil.offlineUuid(player.getUsername()), player.getUsername(),
                                    hash, StoredPlayer.TYPE_OFFLINE, session.ip)
                            .thenAccept(result -> {
                                if (result == DatabaseManager.RegisterResult.OK) {
                                    completeAuth(player, session, "auth.success.register", true);
                                } else if (result == DatabaseManager.RegisterResult.DUPLICATE) {
                                    failRegister(player, session, "error.already-registered", Map.of());
                                } else {
                                    // 真正的数据库故障不能伪装成"昵称已被注册"
                                    failRegister(player, session, "error.server-busy", Map.of());
                                }
                            })
                            .exceptionally(throwable -> {
                                logger.error("[MikuAuth] 注册写入异常: {}", throwable.toString());
                                failRegister(player, session, "error.server-busy", Map.of());
                                return null;
                            });
                } catch (RuntimeException e) {
                    logger.error("[注册] 密码哈希失败: {}", e.getMessage());
                    display.chatAlways(player, "error.server-busy", Map.of());
                } finally {
                    releaseCryptoSlot(session.username);
                }
            });
        } catch (RejectedExecutionException e) {
            releaseCryptoSlot(session.username);
            logger.warn("[注册] 密码哈希队列已满，拒绝 {} 的请求", player.getUsername());
            display.chatAlways(player, "error.server-busy", Map.of());
        }
    }

    // ---------------------------------------------------------------------
    // 修改密码（玩家自助）/ 重置密码（管理员）
    // ---------------------------------------------------------------------

    /**
     * {@code /changepassword <旧密码> <新密码> <确认新密码>}：玩家自助改密。
     *
     * <p>只在玩家<b>已通过认证</b>时可用（认证中的玩家应先用密码登录）。
     * 成功后清除该账号的同 IP 会话免密记录——改密的语义就是"旧凭证一律作废"。
     *
     * <p>旧密码的校验与登录共用 {@link PasswordHasher}，因此从其他插件迁移来的
     * 旧算法哈希（AuthMe 的 {@code $SHA$}/{@code $SHA512$}/MD5）同样可以改密；
     * 写入的新哈希一律是 BCrypt。
     */
    public void handleChangePasswordCommand(Player player, String oldPassword, String newPassword, String confirm) {
        if (!isAllowed(player)) {
            display.chatAlways(player, "error.must-authenticate", Map.of());
            return;
        }
        String username = player.getUsername();
        String ip = player.getRemoteAddress().getAddress().getHostAddress();

        // 新密码：长度/字符集与注册同一套规则
        PasswordPolicy.Violation violation = PasswordPolicy.check(config, newPassword);
        if (violation != null) {
            display.chatAlways(player, violation.messageKey(), violation.placeholders());
            return;
        }
        if (!newPassword.equals(confirm)) {
            display.chatAlways(player, "error.password-mismatch", Map.of());
            return;
        }
        if (oldPassword == null || oldPassword.isEmpty()) {
            display.chatAlways(player, "error.password-empty", Map.of());
            return;
        }
        if (oldPassword.equals(newPassword)) {
            display.chatAlways(player, "error.password-same", Map.of());
            return;
        }
        // 改密同样属于"密码尝试"，纳入跨会话失败计数
        LoginThrottle.Lock lock = throttle.check(ip, username);
        if (lock != null) {
            display.chatAlways(player, "error.locked",
                    Map.of("minutes", String.valueOf(lock.remainingMinutes())));
            return;
        }
        if (!tryAcquireCryptoSlot(username, ip)) {
            display.chatAlways(player, "error.too-fast", Map.of());
            return;
        }
        database.findPlayer(username).thenAccept(existing -> {
            StoredPlayer stored = existing.orElse(null);
            if (stored == null || !stored.hasPassword()) {
                releaseCryptoSlot(username);
                display.chatAlways(player, "changepassword.no-password", Map.of());
                return;
            }
            try {
                cryptoExecutor.execute(() ->
                        changePassword(player, username, ip, stored, oldPassword, newPassword));
            } catch (RejectedExecutionException e) {
                releaseCryptoSlot(username);
                display.chatAlways(player, "error.server-busy", Map.of());
            }
        }).exceptionally(throwable -> {
            logger.error("[MikuAuth] 改密查询异常: {}", throwable.toString());
            releaseCryptoSlot(username);
            display.chatAlways(player, "error.server-busy", Map.of());
            return null;
        });
    }

    /** 线程池内执行改密：校验旧密码 → 写入新哈希 → 清除同 IP 会话。 */
    private void changePassword(Player player, String username, String ip, StoredPlayer stored,
                                String oldPassword, String newPassword) {
        try {
            boolean verified;
            try {
                // 必须与登录走同一个入口（PasswordHasher）：迁移来的账号可能带着
                // AuthMe 的 $SHA$/$SHA512$/MD5 哈希，若此处直接用 BCrypt 校验，
                // 这些玩家能正常登录却永远改不了密码（一直提示"当前密码错误"，
                // 还会累计失败次数直至被临时封禁）
                verified = PasswordHasher.verify(oldPassword, stored.passwordHash());
            } catch (RuntimeException e) {
                logger.warn("[改密] 旧密码校验异常: {}", e.getMessage());
                verified = false;
            }
            if (!verified) {
                LoginThrottle.Lock lock = throttle.recordFailure(ip, username);
                display.chatAlways(player,
                        lock != null ? "changepassword.wrong-locked" : "error.old-password-wrong",
                        lock != null ? Map.of("minutes", String.valueOf(lock.remainingMinutes())) : Map.of());
                return;
            }
            String hash = BCrypt.withDefaults().hashToString(config.bcryptCost(), newPassword.toCharArray());
            database.updatePassword(username, hash)
                    .thenCompose(updated -> {
                        if (updated) {
                            // 改密后清除同 IP 会话：旧会话不应继续免密
                            database.clearSession(username);
                        }
                        return CompletableFuture.completedFuture(updated);
                    })
                    .whenComplete((updated, error) -> {
                        if (error != null) {
                            logger.error("[改密] 写入失败: {}", error.toString());
                            display.chatAlways(player, "error.server-busy", Map.of());
                            return;
                        }
                        if (!Boolean.TRUE.equals(updated)) {
                            display.chatAlways(player, "changepassword.no-password", Map.of());
                            return;
                        }
                        throttle.reset(ip, username);
                        display.chatAlways(player, "changepassword.success", Map.of());
                        logger.info("[改密] {} 已修改密码，其同 IP 会话免密记录已清除", username);
                        audit.record(AuditAction.CHANGE_PASSWORD, username, player.getUniqueId(), ip,
                                "玩家自行修改密码");
                    });
        } finally {
            releaseCryptoSlot(username);
        }
    }

    // ---------------------------------------------------------------------
    // 管理员交互式重置密码（避免明文进入命令历史）
    // ---------------------------------------------------------------------

    /** 等待密码输入的会话：管理员 UUID → 待处理请求。 */
    private final ConcurrentHashMap<UUID, PendingPasswordInput> pendingPasswordInputs =
            new ConcurrentHashMap<>();

    /** 交互式密码输入的有效期（毫秒）。 */
    private static final long PASSWORD_INPUT_TIMEOUT_MILLIS = 60_000L;

    /** 等待输入的状态；只保存目标昵称与过期时间，不保存任何输入内容。 */
    private record PendingPasswordInput(String target, long expireAt) {
    }

    /**
     * 开始交互式重置密码：登记等待状态，实际输入由
     * {@link #consumePasswordInput(Player, String)} 从聊天栏接收。
     *
     * <p>与 {@code setpassword <玩家> <密码>} 的区别在于<b>密码不经过命令行</b>：
     * Velocity 的控制台历史（{@code .console_history}）以"时间戳:命令"格式记录完整
     * 命令行，实测确认——因此命令行传密码会把明文落到磁盘上。
     */
    public void beginPasswordReset(Player admin, String target) {
        pendingPasswordInputs.put(admin.getUniqueId(),
                new PendingPasswordInput(target,
                        System.currentTimeMillis() + PASSWORD_INPUT_TIMEOUT_MILLIS));
    }

    /**
     * 尝试把一条聊天消息当作密码输入消费掉。
     *
     * @return true = 已消费；<b>调用方必须阻止该消息广播</b>，否则密码会暴露给全服玩家
     */
    public boolean consumePasswordInput(Player admin, String message) {
        PendingPasswordInput pending = pendingPasswordInputs.get(admin.getUniqueId());
        if (pending == null) {
            return false;
        }
        // 一次性消费：无论成功与否都不再等待下一次输入，避免误把后续聊天当密码
        pendingPasswordInputs.remove(admin.getUniqueId());
        if (System.currentTimeMillis() > pending.expireAt()) {
            display.chatAlways(admin, "admin.passwd.timeout", Map.of());
            return true;
        }
        // 与玩家自助改密共用同一套策略，避免"管理员能设出玩家设不了的密码"
        PasswordPolicy.Violation violation = PasswordPolicy.check(config, message);
        if (violation != null) {
            display.chatAlways(admin, violation.messageKey(), violation.placeholders());
            return true;
        }
        resetPassword(pending.target(), message).whenComplete((updated, error) -> {
            if (error != null) {
                logger.warn("[管理] 重置 {} 的密码失败: {}", pending.target(), error.toString());
                display.chatAlways(admin, "admin.error", Map.of("reason", "内部错误，详见控制台"));
                return;
            }
            display.chatAlways(admin,
                    updated ? "admin.setpassword.success" : "admin.setpassword.not-found",
                    Map.of("player", pending.target()));
            if (Boolean.TRUE.equals(updated)) {
                audit.record(AuditAction.ADMIN_ACTION, pending.target(), null, null,
                        "管理员 " + admin.getUsername() + " 交互式重置了密码");
            }
        });
        return true;
    }

    /**
     * 管理员重置密码：不校验旧密码，直接写入新哈希。
     * 同时清除该账号的同 IP 会话免密记录并解除失败封禁，确保旧会话立即失效。
     *
     * @return true = 账号存在且已更新；false = 账号不存在或没有密码字段
     */
    public CompletableFuture<Boolean> resetPassword(String nickname, String newPassword) {
        CompletableFuture<Boolean> result = new CompletableFuture<>();
        try {
            cryptoExecutor.execute(() -> {
                try {
                    String hash = BCrypt.withDefaults()
                            .hashToString(config.bcryptCost(), newPassword.toCharArray());
                    database.updatePassword(nickname, hash)
                            .thenCompose(updated -> {
                                if (updated) {
                                    database.clearSession(nickname);
                                }
                                return CompletableFuture.completedFuture(updated);
                            })
                            .whenComplete((updated, error) -> {
                                if (error != null) {
                                    result.completeExceptionally(error);
                                    return;
                                }
                                if (Boolean.TRUE.equals(updated)) {
                                    // 会话已在上一步清除；这里顺带解除该账号的失败封禁
                                    throttle.unlock(nickname);
                                }
                                result.complete(Boolean.TRUE.equals(updated));
                            });
                } catch (Throwable t) {
                    result.completeExceptionally(t);
                }
            });
        } catch (RejectedExecutionException e) {
            result.completeExceptionally(e);
        }
        return result;
    }

    /** 管理员解锁：参数为玩家名或 IP，返回是否确实清理了计数。 */
    public boolean unlock(String subject) {
        return throttle.unlock(subject);
    }

    /** 由定时任务调用：按保留天数清理审计日志。 */
    public void purgeAuditLogs() {
        audit.purgeExpired();
    }

    /** 认证方式 → 审计事件类型。 */
    private static AuditAction auditActionFor(String messageKey) {
        return switch (messageKey) {
            case "auth.auto.premium" -> AuditAction.LOGIN_PREMIUM;
            case "auth.auto.bedrock" -> AuditAction.LOGIN_BEDROCK;
            case "auth.auto.session" -> AuditAction.LOGIN_SESSION;
            case "auth.success.register" -> AuditAction.REGISTER;
            default -> AuditAction.LOGIN_SUCCESS;
        };
    }

    /** 认证方式 → 审计补充说明（便于人工阅读，不必回查代码）。 */
    private static String auditDetailFor(String messageKey) {
        return switch (messageKey) {
            case "auth.auto.premium" -> "正版会话校验通过";
            case "auth.auto.bedrock" -> "基岩版（Floodgate）免密";
            case "auth.auto.session" -> "同 IP 会话免密";
            case "auth.success.register" -> "注册并登录";
            default -> "密码登录";
        };
    }

    // ---------------------------------------------------------------------
    // 认证完成 / 失败
    // ---------------------------------------------------------------------

    /**
     * 完成认证：登记会话、提示、送离认证服。
     *
     * @param passwordVerified 本次是否由<b>密码</b>验证通过（登录/注册）。
     *                         仅此时才重置失败计数并刷新同 IP 会话；
     *                         免密路径（正版/基岩/同 IP 会话）不重置、不刷新——
     *                         否则会话"滚雪球"：只要玩家持续进入就永不过期，
     *                         而且失败计数会被免密登录顺手清零。
     */
    private void completeAuth(Player player, AuthSession session, String messageKey, boolean passwordVerified) {
        session.allowed = true;
        session.dialogOpen = false;
        // 先登记"已完成认证"再移除会话：顺序颠倒时，若恰有 ServerConnectedEvent 在窗口内进来，
        // 会重新走一遍认证流程（离线玩家被二次要求登录）
        authenticated.add(player.getUniqueId());
        sessions.remove(player.getUniqueId(), session);
        // 审计：成功路径统一在此记录，事件类型由 messageKey 映射出认证方式
        audit.record(auditActionFor(messageKey), player.getUsername(), player.getUniqueId(),
                session.ip, auditDetailFor(messageKey));

        if (passwordVerified) {
            // 密码认证成功：清空该 IP/账号的失败计数
            throttle.reset(session.ip, player.getUsername());
            // 同 IP 会话：仅密码认证成功后写入（免密进入不续期，到期必须重新输密码）
            if (config.sessionEnabled()) {
                long expiresAt = System.currentTimeMillis() + config.sessionDurationMinutes() * 60_000L;
                database.saveSession(player.getUsername(), session.ip, expiresAt);
            }
        }
        database.recordLogin(player.getUsername(), session.ip);

        display.showSuccess(player, messageKey + ".title", messageKey + ".subtitle",
                Map.of("player", player.getUsername()));
        display.chatAlways(player, messageKey + ".chat", Map.of());

        transfer.schedule(player);
    }

    /** 登录失败反馈：聊天提示 + 支持时重开 Dialog（错误文本追加进对话框正文）。 */
    private void failLogin(Player player, AuthSession session, String errorKey,
                           Map<String, String> placeholders, boolean retryDialog) {
        display.chat(player, errorKey, placeholders);
        if (hasNicknameConflict(session)) {
            // 该昵称当前对应一个正版账号：正版玩家会被要求输入离线账号的密码
            display.chat(player, "error.password-wrong-conflict", Map.of());
        }
        if (retryDialog && player.isActive() && "login".equals(session.textKey)) {
            String extra = hasNicknameConflict(session)
                    ? renderText(errorKey, placeholders) + "\n" + renderText("error.password-wrong-conflict", Map.of())
                    : renderText(errorKey, placeholders);
            String error = dialogService.showLogin(player, extra);
            if (error == null) {
                session.dialogOpen = true;
                display.enterSilent(player);
            } else {
                // 重开失败必须解除静默：否则 DisplayManager 仍处于静默态，
                // 之后所有聊天提示都会被丢弃，玩家将看不到任何反馈
                display.exitSilent(player);
            }
        }
    }

    /** 注册失败反馈：聊天提示 + 支持时重开注册 Dialog。 */
    private void failRegister(Player player, AuthSession session, String errorKey,
                              Map<String, String> placeholders) {
        display.chat(player, errorKey, placeholders);
        if (player.isActive() && "register".equals(session.textKey)) {
            String error = dialogService.showRegister(player,
                    renderText(errorKey, placeholders));
            if (error == null) {
                session.dialogOpen = true;
                display.enterSilent(player);
            } else {
                display.exitSilent(player);
            }
        }
    }

    /** 渲染文本键为原始字符串（供 Dialog 正文追加），替换占位符。 */
    private String renderText(String key, Map<String, String> placeholders) {
        String text = messages.raw(key);
        if (placeholders != null) {
            for (Map.Entry<String, String> entry : placeholders.entrySet()) {
                text = text.replace("{" + entry.getKey() + "}", entry.getValue() == null ? "" : entry.getValue());
            }
        }
        return text;
    }

    /** 踢出玩家（无附加说明）。 */
    public void kick(Player player, String messageKey) {
        kick(player, messageKey, null);
    }

    /**
     * 踢出玩家；若存在昵称冲突（昵称当前对应正版账号），在踢出原因后附加说明，
     * 帮助正版玩家理解被要求输入密码的原因。
     */
    public void kick(Player player, String messageKey, AuthSession session) {
        cleanup(player.getUniqueId());
        // 审计：认证超时是"玩家卡在 limbo"的典型症状，值得单独留痕
        if ("kick.auth-timeout".equals(messageKey)) {
            audit.record(AuditAction.KICK_TIMEOUT, player.getUsername(), player.getUniqueId(),
                    session != null ? session.ip : remoteIpOf(player), "认证超时未完成");
        }
        Component reason = messages.component(messageKey);
        if (session != null && hasNicknameConflict(session)) {
            reason = Component.text().append(reason)
                    .append(Component.newline())
                    .append(messages.component("error.password-wrong-conflict"))
                    .build();
        }
        player.disconnect(reason);
    }

    /** 取玩家来源 IP（失败返回 null）。 */
    private static String remoteIpOf(Player player) {
        try {
            var address = player.getRemoteAddress();
            return address == null || address.getAddress() == null
                    ? null : address.getAddress().getHostAddress();
        } catch (Throwable t) {
            return null;
        }
    }

    // ---------------------------------------------------------------------
    // Dialog 关闭检测（PacketEvents 回调）
    // ---------------------------------------------------------------------

    /**
     * 对话框关闭回调（由 /mikuauth-close 命令触发，或对话框未能锁定输入时
     * 收到的防御性聊天包触发）：解除静默并给出聊天栏用法提示。
     */
    public void handleClientActivity(Player player) {
        AuthSession session = sessions.get(player.getUniqueId());
        if (session == null || !session.dialogOpen) {
            return;
        }
        session.dialogOpen = false;
        display.exitSilent(player);
        display.chat(player, session.textKey + ".chat-usage", Map.of());
    }

    // ---------------------------------------------------------------------
    // 状态查询与命令拦截
    // ---------------------------------------------------------------------

    /** 玩家是否已通过认证（或根本不需要认证）。 */
    public boolean isAllowed(Player player) {
        AuthSession session = sessions.get(player.getUniqueId());
        return session == null || session.allowed;
    }

    /** 玩家是否已有认证会话（进入认证服只处理一次）。 */
    public boolean hasSession(Player player) {
        return sessions.containsKey(player.getUniqueId());
    }

    // ---------------------------------------------------------------------
    // 心跳：超时踢出 + 显示刷新
    // ---------------------------------------------------------------------

    /** 每秒心跳。 */
    public void tick() {
        if (!sessions.isEmpty()) {
            int timeout = config.authTimeoutSeconds();
            long now = System.currentTimeMillis();
            for (var entry : sessions.entrySet()) {
                AuthSession session = entry.getValue();
                if (session.allowed) {
                    continue;
                }
                Player player = server.getPlayer(entry.getKey()).orElse(null);
                if (player == null) {
                    sessions.remove(entry.getKey());
                    continue;
                }
                if (timeout > 0 && now - session.connectedAt > timeout * 1000L) {
                    kick(player, "kick.auth-timeout", session);
                    continue;
                }
                display.tick(player);
            }
        }
        transfer.retryStuck();
        // 清理过期的失败计数（低频操作，心跳里做即可）
        if (throttlePurgeTick++ % 60 == 0) {
            throttle.purge();
        }
    }

    /** 失败计数清理的节流计数（每 60 次心跳清理一次）。 */
    private int throttlePurgeTick;

    // ---------------------------------------------------------------------
    // 清理
    // ---------------------------------------------------------------------

    /** 玩家断开连接清理。 */
    public void handleDisconnect(String username, UUID playerId) {
        cleanup(playerId);
        authenticated.remove(playerId);
        transfer.forget(playerId);
        premium.forget(playerId, username);


        // 会话免密标记：玩家在建立连接前断线时清理（正常路径已由 handleConnected 消费）
        sessionVerifiedNames.remove(MikuConfig.normalize(username));
    }

    private void cleanup(UUID playerId) {
        sessions.remove(playerId);
        transfer.forget(playerId);
        Player player = server.getPlayer(playerId).orElse(null);
        if (player != null) {
            display.stopTracking(player);
        }
    }

    // ---------------------------------------------------------------------
    // 内部
    // ---------------------------------------------------------------------

    /**
     * 解析认证后目标服务器（委托 {@link TransferCoordinator}）。
     * 供初始调度使用：免密玩家跳过认证服时直连该目标。
     */
    public RegisteredServer resolvePostAuthTarget() {
        return transfer.resolveTarget();
    }

    /**
     * 为异步链路挂异常兜底：失败时记录错误日志并返回 fallback。
     *
     * <p>认证链路上的 future 一旦异常完成且无人处理，就会让事件任务永久挂起
     * （玩家卡在登录界面直到客户端超时），因此所有"必须完成"的链路都要过这里。
     */
    private <T> CompletableFuture<T> withFallback(CompletableFuture<T> future, T fallback, String action) {
        return future.exceptionally(throwable -> {
            logger.error("[MikuAuth] {} 异常，已降级处理: {}", action, throwable.toString());
            return fallback;
        });
    }

    /** 丢弃指定昵称的缓存决策（正版绑定被管理员清除后立即生效）。 */
    public void invalidateLoginDecision(String username) {
        String key = MikuConfig.normalize(username);
        lastLoginModes.remove(key);
        premium.forgetExpectation(username);
    }

    /**
     * 申请一次密码计算名额：同一 IP 的最小提交间隔 + 同一账号的并发去重。
     *
     * <p>BCrypt 是 CPU 密集型操作（cost=10 约 60~100ms），必须防止单 IP 洪泛把
     * 线程池与内存拖垮；这里做的是"准入控制"，命中节流时调用方应提示玩家稍后再试。
     *
     * @return true = 已获得名额（调用方必须在结束后调用 {@link #releaseCryptoSlot}）
     */
    private boolean tryAcquireCryptoSlot(String nickname, String ip) {
        long now = System.currentTimeMillis();
        if (ip != null) {
            Long last = ipCryptoThrottle.get(ip);
            if (last != null && now - last < IP_CRYPTO_THROTTLE_MILLIS) {
                return false;
            }
            ipCryptoThrottle.put(ip, now);
            if (ipCryptoThrottle.size() > IP_THROTTLE_MAX_ENTRIES) {
                ipCryptoThrottle.values().removeIf(at -> now - at > IP_THROTTLE_RETAIN_MILLIS);
            }
        }
        return cryptoInFlight.add(MikuConfig.normalize(nickname));
    }

    private void releaseCryptoSlot(String nickname) {
        cryptoInFlight.remove(MikuConfig.normalize(nickname));
    }

    /** 停止服务。 */
    public void shutdown() {
        cryptoExecutor.shutdownNow();
    }
}
