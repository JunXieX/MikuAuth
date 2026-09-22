package cn.miku.auth.auth;

import cn.miku.auth.audit.BackendKickLog;
import cn.miku.auth.config.MikuConfig;
import cn.miku.auth.config.MikuMessages;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.api.proxy.ServerConnection;
import com.velocitypowered.api.proxy.server.RegisteredServer;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.serializer.plain.PlainTextComponentSerializer;
import net.kyori.adventure.title.Title;
import org.slf4j.Logger;

import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 认证后转服调度：把通过认证的玩家送到目标服务器，并对滞留者自动重试。
 *
 * <p>从 {@link AuthManager} 抽出的独立模块，职责单一且不依赖认证状态机——
 * 因此可以单独测试（目标服解析优先级、滞留判定、服务器归属判断）。
 *
 * <p><b>为什么要延迟转服</b>：免密路径在 {@code ServerConnectedEvent} 处理栈内同步完成认证，
 * 若立即发起连接请求，会与认证服（尤其 limbo）刚发出的 Join Game 包竞争——
 * 基岩版玩家经 Geyser 转换时会话尚未稳定，请求容易被吞，玩家会永远滞留在认证服。
 *
 * <p><b>失败分两类处理</b>（2026-09-22 起）：
 * <ol>
 *   <li><b>目标服明确拒绝</b>（{@code Result#getReasonComponent()} 非空，即目标服自己发了
 *       Disconnect 包）：原因<b>多通道"必达"</b>给玩家（聊天栏 + Title/ActionBar +
 *       断开画面）并<b>停止重试</b>——重试只会被同样拒绝，还会每 5 秒在目标服日志里多刷一次
 *       登录记录；</li>
 *   <li><b>连接层面的故障</b>（目标服离线、连接被意外关闭等，没有原因）：保留挂起标记，
 *       由心跳按 {@link #TRANSFER_RETRY_MILLIS} 间隔重试，直到玩家确实离开认证服或断开连接。</li>
 * </ol>
 *
 * <p><b>为什么被拒绝时还要主动断开玩家</b>（2026-09-22 线上复现）：
 * Velocity 对"目标服明确拒绝"走的是 <b>safe</b> 路径
 * （反编译核对 {@code ConnectionRequestResults.forDisconnect} → {@code safe=true}），
 * 它<b>不会</b>替玩家发 Disconnect 包；目标服那条连接关掉后，玩家只剩一个空荡荡的认证服。
 * 此时若客户端的聊天栏恰处在切服/配置阶段、或连接随即被关闭，聊天内容就永远看不到，
 * 玩家只看到客户端默认的"连接中断"。把完整原因（谁拒的 + 目标服原文 + 处理提示）交给
 * {@code player.disconnect(...)}，断开画面是唯一"必达"的展示面。
 */
public final class TransferCoordinator {

    /** 转服延迟毫秒：避开认证服 Join Game 包与（基岩版）Geyser 会话建立窗口。 */
    private static final long TRANSFER_DELAY_MILLIS = 400;
    /** 心跳滞留重试间隔：认证完成但仍停在认证服超过该时长则再次尝试送服。 */
    private static final long TRANSFER_RETRY_MILLIS = 5000;

    private final ProxyServer server;
    private final Object plugin;
    private final MikuConfig config;
    private final MikuMessages messages;
    private final BackendKickLog kickLog;
    private final Logger logger;

    /** 待转服玩家 → 最近一次送服尝试时间戳。 */
    private final ConcurrentHashMap<UUID, Long> pending = new ConcurrentHashMap<>();

    public TransferCoordinator(ProxyServer server, Object plugin, MikuConfig config,
                               MikuMessages messages, BackendKickLog kickLog, Logger logger) {
        this.server = server;
        this.plugin = plugin;
        this.config = config;
        this.messages = messages;
        this.kickLog = kickLog;
        this.logger = logger;
    }

    // ---------------------------------------------------------------------
    // 对外动作
    // ---------------------------------------------------------------------

    /**
     * 认证完成后延迟送离认证服。
     *
     * <p>若玩家已在目标服（正版/基岩/会话免密直连场景），{@link #doTransfer} 会直接返回。
     */
    public void schedule(Player player) {
        pending.put(player.getUniqueId(), System.currentTimeMillis());
        server.getScheduler()
                .buildTask(plugin, () -> doTransfer(player))
                .delay(Duration.ofMillis(TRANSFER_DELAY_MILLIS))
                .schedule();
    }

    /**
     * 心跳滞留重试：已认证完成但超过重试间隔仍停留在认证服的玩家，再次尝试送离
     * （覆盖转服请求被吞、目标服瞬时不可达等情况）。
     */
    public void retryStuck() {
        if (pending.isEmpty()) {
            return;
        }
        long now = System.currentTimeMillis();
        for (var entry : pending.entrySet()) {
            Player player = server.getPlayer(entry.getKey()).orElse(null);
            if (player == null) {
                pending.remove(entry.getKey());
                continue;
            }
            if (!isOnAuthServer(player)) {
                pending.remove(entry.getKey()); // 已离开认证服
                continue;
            }
            if (now - entry.getValue() >= TRANSFER_RETRY_MILLIS) {
                entry.setValue(now);
                doTransfer(player);
            }
        }
    }

    /** 玩家断线：丢弃其挂起记录（不干扰已断开的连接）。 */
    public void forget(UUID playerId) {
        pending.remove(playerId);
    }

    /**
     * 解析认证后目标服务器：优先 {@code fallback-server}，其次 velocity.toml 的 try 列表
     * 中第一个存在的非认证服。
     *
     * @return null = 没有任何可用目标服（插件启动时已强校验过，此处为运行期兜底）
     */
    public RegisteredServer resolveTarget() {
        String fallbackName = config.fallbackServer();
        if (fallbackName != null && !fallbackName.isEmpty()) {
            RegisteredServer configured = server.getServer(fallbackName).orElse(null);
            if (configured != null) {
                return configured;
            }
            logger.warn("[调度] 配置的 fallback-server '" + fallbackName + "' 不存在，改用 try 列表");
        }
        for (String name : server.getConfiguration().getAttemptConnectionOrder()) {
            if (!name.equalsIgnoreCase(config.authServer())) {
                RegisteredServer candidate = server.getServer(name).orElse(null);
                if (candidate != null) {
                    return candidate;
                }
            }
        }
        return null;
    }

    /** 该玩家当前是否仍有待转服记录（诊断用）。 */
    public boolean isPending(UUID playerId) {
        return pending.containsKey(playerId);
    }

    // ---------------------------------------------------------------------
    // 服务器归属判断（转服与认证流程都要用，故放在这里统一提供）
    // ---------------------------------------------------------------------

    /** 玩家当前是否位于认证服。 */
    public boolean isOnAuthServer(Player player) {
        return isOnServer(player, config.authServer());
    }

    /** 玩家当前是否位于指定名称的服务器（大小写不敏感）。 */
    public static boolean isOnServer(Player player, String serverName) {
        return player.getCurrentServer()
                .map(ServerConnection::getServerInfo)
                .map(info -> info.getName().equalsIgnoreCase(serverName))
                .orElse(false);
    }

    // ---------------------------------------------------------------------
    // 内部
    // ---------------------------------------------------------------------

    /** 执行转服：解析目标、跳过"已在目标服"场景、校验结果，按失败类型决定转发原因还是重试。 */
    private void doTransfer(Player player) {
        if (pending.remove(player.getUniqueId()) == null || !player.isActive()) {
            return; // 已取消（断线清理）
        }
        RegisteredServer target = resolveTarget();
        if (target == null) {
            logger.warn("[调度] 未找到认证后目标服务器（请检查 config.yml 的 fallback-server"
                    + " 或 velocity.toml 的 try 列表），" + player.getUsername() + " 留在当前服务器");
            return;
        }
        String serverName = target.getServerInfo().getName();
        // 免密直连场景（正版/基岩/会话免密）：玩家已在目标服，无需再转
        if (isOnServer(player, serverName)) {
            return;
        }
        player.createConnectionRequest(target).connect().whenComplete((result, throwable) -> {
            if (throwable == null && result != null && result.isSuccessful()) {
                return;
            }
            if (!player.isActive()) {
                return;
            }
            // 目标服主动拒绝时，Velocity 会把它的 Disconnect 包内容放进 Result#getReasonComponent
            // （ConnectionRequestResults.forDisconnect：status=SERVER_DISCONNECTED、reason=踢出原因、
            //  safe=true ⇒ Velocity 不会替玩家发 Disconnect 包）。
            // 这条原因只有插件看得到：玩家此刻还留在认证服，踢出发生在去目标服的那条连接上。
            Optional<Component> reason = result != null ? result.getReasonComponent() : Optional.empty();
            if (reason.isPresent()) {
                forwardBackendRejection(player, serverName, reason.get());
                return; // 明确拒绝：不再重试（重试必然得到同样的踢出，只会在目标服多刷登录记录）
            }
            String cause = throwable != null
                    ? throwable.getClass().getSimpleName()
                    : String.valueOf(result.getStatus());
            logger.warn("[调度] {} 转服至 {} 失败（{}），将在心跳中自动重试",
                    player.getUsername(), serverName, cause);
            // 保留/恢复挂起标记，由 retryStuck() 继续重试
            pending.putIfAbsent(player.getUniqueId(), System.currentTimeMillis());
        });
    }

    /**
     * 把目标服的拒绝原因"必达"给玩家，并留档。
     *
     * <p>玩家坐在认证服里，对"为什么进不去"毫无感知——这里走三个通道，保证至少一处可见：
     * <ol>
     *   <li>聊天栏（保留原行为）：说明是哪个服拒的 + 原因原文 + 处理提示；</li>
     *   <li>Title/ActionBar：切服/配置阶段聊天栏可能被吞时的醒目补充；</li>
     *   <li><b>{@code player.disconnect(完整原因)}（必达兜底）</b>：把完整原因（谁拒的 +
     *       原因原文 + 处理提示）交给断开画面。玩家已通过认证却进不去目标服，留在认证服里
     *       没有任何出路，直接断开并给出原因比"干等"更清晰，也彻底杜绝"只看到连接中断"。</li>
     * </ol>
     *
     * <p>通道 1/2 属于"尽力而为"：任何异常都被吞掉，绝不能阻断"必达"的断开兜底。
     */
    private void forwardBackendRejection(Player player, String serverName, Component reason) {
        Component header = messages.component("transfer.rejected-header", Map.of("server", serverName));
        Component hint = messages.component("transfer.rejected-hint");
        // 完整原因：谁拒的 + 目标服原文 + 处理提示（断开画面逐行展示）
        Component full = Component.text()
                .append(header)
                .append(Component.newline())
                .append(reason)
                .append(Component.newline())
                .append(hint)
                .build();

        String plain = PlainTextComponentSerializer.plainText().serialize(reason)
                .replaceAll("\\R+", " | ").trim();
        // 诊断：转发这一刻玩家在哪台服、连接是否还活着 —— 下次若复现，一眼可定位
        String currentServer = player.getCurrentServer()
                .map(connection -> connection.getServerInfo().getName())
                .orElse("（未连接）");
        logger.warn("[调度] {} 被 {} 拒绝进入：{}（转发时所在服务器={}，连接 active={}；"
                        + "原因已转发 Chat/Title 并在断开画面展示）",
                player.getUsername(), serverName,
                plain.isEmpty() ? "（目标服未提供文本）" : plain,
                currentServer, player.isActive());

        // 通道 1/2（尽力而为）：聊天栏 + ActionBar + （启用时）Title
        try {
            player.sendMessage(header);
            player.sendMessage(reason);
            player.sendMessage(hint);
            player.sendActionBar(hint);
            if (config.titleEnabled()) {
                player.showTitle(Title.title(header, hint, Title.Times.times(
                        Duration.ofMillis(200), Duration.ofMillis(3000), Duration.ofMillis(500))));
            }
        } catch (RuntimeException e) {
            logger.warn("[调度] {} 的拒绝原因在聊天栏/Title 通道发送失败（{}），改由断开画面兜底",
                    player.getUsername(), e.getMessage());
        }

        // 先落审计：backend-kicks.log 是事后排障的唯一线索，绝不能被下面 disconnect 的异常吞掉
        kickLog.record(player.getUsername(), serverName, plain);

        // 通道 3（必达）：断开连接，把完整原因交给断开画面 —— 绝不再让玩家只看到"连接中断"
        player.disconnect(full);
    }
}
