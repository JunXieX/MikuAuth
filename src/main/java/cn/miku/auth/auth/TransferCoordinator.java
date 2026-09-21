package cn.miku.auth.auth;

import cn.miku.auth.config.MikuConfig;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.api.proxy.ServerConnection;
import com.velocitypowered.api.proxy.server.RegisteredServer;
import org.slf4j.Logger;

import java.time.Duration;
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
 * <p><b>为什么要重试</b>：即使延迟后发起，仍可能因目标服瞬时不可达、请求被吞等原因失败。
 * 因此失败时保留挂起标记，由心跳按 {@link #TRANSFER_RETRY_MILLIS} 间隔重试，
 * 直到玩家确实离开认证服或断开连接。
 */
public final class TransferCoordinator {

    /** 转服延迟毫秒：避开认证服 Join Game 包与（基岩版）Geyser 会话建立窗口。 */
    private static final long TRANSFER_DELAY_MILLIS = 400;
    /** 心跳滞留重试间隔：认证完成但仍停在认证服超过该时长则再次尝试送服。 */
    private static final long TRANSFER_RETRY_MILLIS = 5000;

    private final ProxyServer server;
    private final Object plugin;
    private final MikuConfig config;
    private final Logger logger;

    /** 待转服玩家 → 最近一次送服尝试时间戳。 */
    private final ConcurrentHashMap<UUID, Long> pending = new ConcurrentHashMap<>();

    public TransferCoordinator(ProxyServer server, Object plugin, MikuConfig config, Logger logger) {
        this.server = server;
        this.plugin = plugin;
        this.config = config;
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

    /** 执行转服：解析目标、跳过"已在目标服"场景、校验结果，失败交给心跳重试。 */
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
        // 免密直连场景（正版/基岩/会话免密）：玩家已在目标服，无需再转
        if (isOnServer(player, target.getServerInfo().getName())) {
            return;
        }
        player.createConnectionRequest(target).connect().whenComplete((result, throwable) -> {
            boolean success = throwable == null && result != null && result.isSuccessful();
            if (!success && player.isActive()) {
                String reason = throwable != null
                        ? throwable.getClass().getSimpleName()
                        : String.valueOf(result.getStatus());
                logger.warn("[调度] {} 转服至 {} 失败（{}），将在心跳中自动重试",
                        player.getUsername(), target.getServerInfo().getName(), reason);
                // 保留/恢复挂起标记，由 retryStuck() 继续重试
                pending.putIfAbsent(player.getUniqueId(), System.currentTimeMillis());
            }
        });
    }
}
