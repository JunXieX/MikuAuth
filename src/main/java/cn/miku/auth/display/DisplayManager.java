package cn.miku.auth.display;

import cn.miku.auth.config.MikuConfig;
import cn.miku.auth.config.MikuMessages;
import com.velocitypowered.api.proxy.Player;
import net.kyori.adventure.bossbar.BossBar;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.title.Title;

import java.time.Duration;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 认证提示显示管理：Title + BossBar + 聊天栏。
 *
 * <p><b>静默规则</b>（核心需求）：玩家正在使用 Dialog 对话框时，
 * 聊天栏 / BossBar / Title 一律不提示、不更新（模态界面下玩家不可见，
 * 且避免关闭后堆叠过期信息）；仅当玩家关闭对话框或无法使用对话框时才恢复提示。
 *
 * <p>性能：每个待认证玩家一个状态对象与一个 BossBar 实例，心跳更新为
 * O(在线待认证玩家数) 的轻量遍历；认证完成即刻清理，无常驻对象残留。
 */
public final class DisplayManager {

    /** Title 重发间隔（秒）：须小于 Title 停留时长（3.8s），否则会出现显示空窗闪烁。 */
    private static final int TITLE_REFRESH_SECONDS = 3;

    private final MikuConfig config;
    private final MikuMessages messages;

    /** 待认证玩家的显示状态。 */
    private final ConcurrentHashMap<UUID, TrackedDisplay> tracked = new ConcurrentHashMap<>();

    /**
     * 处于静默态的玩家（Dialog 打开中）。
     *
     * <p><b>为什么不复用 {@link TrackedDisplay#silent}</b>：跟踪条目只在显示开关打开时创建
     * （{@code display.title} 与 {@code display.bossbar} 全关时 {@code tracked} 为空），
     * 而"对话框期间不发聊天提示"是独立需求 —— 复用会让该规则在这类服务器上整体失效，
     * 玩家会在对话框关闭后看到一堆本应被抑制的错误/用法提示。
     */
    private final java.util.Set<UUID> silentPlayers = ConcurrentHashMap.newKeySet();

    /**
     * 单个玩家的显示状态。
     *
     * <p><b>线程模型</b>：{@code silent} 由事件线程写（{@code enterSilent}/{@code exitSilent}），
     * {@code tick()} 由调度线程读写，因此可变字段必须 volatile，否则可能出现
     * "对话框关闭后 Title/BossBar 不恢复"的可见性问题。
     */
    private static final class TrackedDisplay {
        final BossBar bossBar;
        final long deadlineMillis;
        final long totalMillis;
        final String textKey;
        final Map<String, String> placeholders;
        /** Dialog 打开中 = 静默。 */
        volatile boolean silent;
        volatile int titleCounter;
        /** 上次心跳渲染的剩余秒数（-1 = 不限时），秒数不变则跳过 BossBar 文本重建。 */
        volatile long lastRemainSeconds = -2;

        TrackedDisplay(BossBar bossBar, long deadlineMillis, String textKey, Map<String, String> placeholders) {
            this.bossBar = bossBar;
            this.deadlineMillis = deadlineMillis;
            this.totalMillis = Math.max(1, deadlineMillis - System.currentTimeMillis());
            this.textKey = textKey;
            this.placeholders = placeholders == null ? Map.of() : placeholders;
        }
    }

    public DisplayManager(MikuConfig config, MikuMessages messages) {
        this.config = config;
        this.messages = messages;
    }

    // ---------------------------------------------------------------------
    // 跟踪生命周期
    // ---------------------------------------------------------------------

    /**
     * 开始跟踪一个待认证玩家：显示 Title 与 BossBar 倒计时。
     *
     * @param player         目标玩家
     * @param textKey        文本键基名（如 "login" → 取 login.bossbar / login.title / login.subtitle）
     * @param placeholders   文本占位符
     * @param timeoutSeconds 认证超时秒数；0 表示不限时（BossBar 常驻满进度）
     */
    public void startTracking(Player player, String textKey, Map<String, String> placeholders, int timeoutSeconds) {
        if (!config.bossBarEnabled() && !config.titleEnabled()) {
            return;
        }
        long deadline = timeoutSeconds > 0
                ? System.currentTimeMillis() + timeoutSeconds * 1000L
                : 0L;
        // 初始占位符即包含 seconds：避免 BossBar 首次显示时出现未替换的 {seconds} 字面文本
        Map<String, String> dynamic = new java.util.HashMap<>(
                placeholders == null ? Map.of() : placeholders);
        dynamic.put("seconds", String.valueOf(Math.max(0, timeoutSeconds)));
        Map<String, String> bossBarPlaceholders = Map.copyOf(dynamic);

        TrackedDisplay display = new TrackedDisplay(
                createBossBar(textKey, bossBarPlaceholders, timeoutSeconds > 0),
                deadline, textKey, dynamic);
        tracked.put(player.getUniqueId(), display);
        if (config.bossBarEnabled()) {
            player.showBossBar(display.bossBar);
        }
        sendTitle(player, display);
    }

    /** 进入静默：Dialog 对话框打开，隐藏 Title 与 BossBar，暂停一切提示更新。 */
    public void enterSilent(Player player) {
        silentPlayers.add(player.getUniqueId());
        TrackedDisplay display = tracked.get(player.getUniqueId());
        if (display == null || display.silent) {
            // display == null：显示开关全关，没有跟踪条目；但静默状态已在上面记下，
            // 对话框期间的聊天提示仍会被抑制
            return;
        }
        display.silent = true;
        player.clearTitle();
        player.hideBossBar(display.bossBar);
    }

    /** 退出静默：对话框已关闭或不可用，立即恢复全部提示。 */
    public void exitSilent(Player player) {
        silentPlayers.remove(player.getUniqueId());
        TrackedDisplay display = tracked.get(player.getUniqueId());
        if (display == null || !display.silent) {
            return;
        }
        display.silent = false;
        if (config.bossBarEnabled()) {
            player.showBossBar(display.bossBar);
        }
        sendTitle(player, display);
    }

    /** 是否处于静默状态（Dialog 打开中）。 */
    public boolean isSilent(UUID playerId) {
        return silentPlayers.contains(playerId);
    }

    /**
     * 是否正在跟踪该玩家的 Title/BossBar 显示。
     *
     * <p>注意与 {@link #isSilent} 的区别：跟踪条目只在 {@code display.title} 或
     * {@code display.bossbar} 至少一项开启时才会创建，因此两者相互独立。
     */
    public boolean isTracking(UUID playerId) {
        return tracked.containsKey(playerId);
    }

    /** 显示认证成功 Title 并结束跟踪（静默状态下由调用方决定何时展示）。 */
    public void showSuccess(Player player, String titleKey, String subKey, Map<String, String> placeholders) {
        stopTracking(player);
        if (config.titleEnabled()) {
            Map<String, String> safe = placeholders == null ? Map.of() : placeholders;
            player.showTitle(Title.title(
                    messages.component(titleKey, safe),
                    messages.component(subKey, safe),
                    Title.Times.times(Duration.ofMillis(200), Duration.ofMillis(2500), Duration.ofMillis(500))));
        }
    }

    /** 结束跟踪并清理显示。 */
    public void stopTracking(Player player) {
        UUID playerId = player.getUniqueId();
        silentPlayers.remove(playerId);
        TrackedDisplay display = tracked.remove(playerId);
        if (display != null) {
            player.hideBossBar(display.bossBar);
            player.clearTitle();
        }
    }

    /**
     * 结束跟踪（按 UUID）。
     *
     * <p><b>断线路径必须用它</b>：Velocity 触发 {@code DisconnectEvent} 时玩家已经不在代理的
     * 注册表里（拿不到 {@code Player} 对象），旧实现只有 {@code stopTracking(Player)}，
     * 于是"待认证期间断线"的玩家条目永久留在跟踪表里 —— BossBar 与占位符 Map 随
     * 不同玩家数单调增长。连接已断，客户端侧无需再 hide，只需把条目移除。
     */
    public void stopTracking(UUID playerId) {
        silentPlayers.remove(playerId);
        tracked.remove(playerId);
    }

    // ---------------------------------------------------------------------
    // 聊天提示（尊重静默状态）
    // ---------------------------------------------------------------------

    /** 发送带前缀的聊天提示；Dialog 打开期间不发送。 */
    public void chat(Player player, String key, Map<String, String> placeholders) {
        if (!isSilent(player.getUniqueId())) {
            player.sendMessage(messages.prefixed(key, placeholders));
        }
    }

    /** 无条件发送聊天提示（认证成功、踢出等结论性消息不受静默限制）。 */
    public void chatAlways(Player player, String key, Map<String, String> placeholders) {
        player.sendMessage(messages.prefixed(key, placeholders));
    }

    // ---------------------------------------------------------------------
    // 心跳：每秒由 AuthManager.tick() 对"待认证玩家"调用（不是全部在线玩家）
    // ---------------------------------------------------------------------

    /** 更新 BossBar 倒计时文本与进度，并周期性重发 Title。静默期间跳过。 */
    public void tick(Player player) {
        TrackedDisplay display = tracked.get(player.getUniqueId());
        if (display == null || display.silent) {
            return;
        }
        long now = System.currentTimeMillis();
        long remainSeconds = display.deadlineMillis > 0
                ? Math.max(0, (display.deadlineMillis - now) / 1000L)
                : -1;

        if (config.bossBarEnabled()) {
            if (remainSeconds >= 0) {
                // 剩余秒数变化才重建文本组件（MiniMessage 渲染有开销，避免每秒重复）
                if (remainSeconds != display.lastRemainSeconds) {
                    display.lastRemainSeconds = remainSeconds;
                    display.bossBar.name(messages.component(display.textKey + ".bossbar",
                            mergeWith(display.placeholders, "seconds", String.valueOf(remainSeconds))));
                }
                display.bossBar.progress(Math.min(1f, remainSeconds * 1000L / (float) display.totalMillis));
            } else {
                // 不限时：切换为静态文本（无 {seconds}），仅设置一次
                if (display.lastRemainSeconds != -1) {
                    display.lastRemainSeconds = -1;
                    display.bossBar.name(messages.component(display.textKey + ".bossbar-static"));
                }
                display.bossBar.progress(1f);
            }
        }
        display.titleCounter++;
        if (config.titleEnabled() && display.titleCounter % TITLE_REFRESH_SECONDS == 0) {
            sendTitle(player, display);
        }
    }

    // ---------------------------------------------------------------------
    // 内部
    // ---------------------------------------------------------------------

    /**
     * 创建 BossBar。
     *
     * @param timed 是否限时（true = 使用带 {seconds} 的倒计时模板；false = 使用静态模板）
     */
    private BossBar createBossBar(String textKey, Map<String, String> placeholders, boolean timed) {
        BossBar.Color color = parseEnum(BossBar.Color.class, config.bossBarColor(), BossBar.Color.YELLOW);
        BossBar.Overlay overlay = parseEnum(BossBar.Overlay.class, config.bossBarOverlay(), BossBar.Overlay.PROGRESS);
        Component name = timed
                ? messages.component(textKey + ".bossbar", placeholders)
                : messages.component(textKey + ".bossbar-static");
        return BossBar.bossBar(name, 1f, color, overlay);
    }

    private void sendTitle(Player player, TrackedDisplay display) {
        if (!config.titleEnabled()) {
            return;
        }
        player.showTitle(Title.title(
                messages.component(display.textKey + ".title", display.placeholders),
                messages.component(display.textKey + ".subtitle", display.placeholders),
                Title.Times.times(Duration.ofMillis(200), Duration.ofMillis(3800), Duration.ofMillis(400))));
    }

    private static Map<String, String> mergeWith(Map<String, String> base, String key, String value) {
        if (value.equals(base.get(key))) {
            return base;
        }
        var merged = new java.util.HashMap<String, String>(base.size() + 1);
        merged.putAll(base);
        merged.put(key, value);
        return Map.copyOf(merged);
    }

    private static <E extends Enum<E>> E parseEnum(Class<E> type, String name, E fallback) {
        try {
            return Enum.valueOf(type, name.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            return fallback;
        }
    }
}
