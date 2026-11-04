package cn.miku.auth.paper;

import org.bukkit.plugin.java.JavaPlugin;

import java.sql.SQLException;

/**
 * MikuAuth-Paper 主类。
 *
 * <p>本版本只实现一种登录模式：<b>进服前认证</b>。玩家停在服务端的配置阶段
 * （画面是"加载地形"、尚未进入世界）时由原生对话框完成注册/登录，
 * 通过之后连接才继续、玩家才真正进入世界。会话判定见 {@link PreJoinGate}。
 *
 * <p>与代理端（Velocity 版）的关系：表结构一致，可以共用同一个账号库；
 * 但同一台服上只应保留一个登录插件，否则会各弹各的框。
 */
public final class MikuAuthPlugin extends JavaPlugin {

    private PaperConfig config;
    private Messages messages;
    private Store store;
    private PreJoinGate gate;

    @Override
    public void onEnable() {
        // 内置 config.yml / messages.yml 落地（已存在则不覆盖）
        saveDefaultConfig();
        this.config = new PaperConfig(this);
        this.messages = new Messages(this);

        try {
            this.store = new Store(getDataFolder(), config, getLogger());
        } catch (SQLException e) {
            getLogger().severe("无法打开数据库: " + e.getMessage());
            getServer().getPluginManager().disablePlugin(this);
            return;
        }

        this.gate = new PreJoinGate(this);
        getServer().getPluginManager().registerEvents(gate, this);

        // 管理命令（Brigadier）：/mikuauth reload|unlock|accounts|audit
        getLifecycleManager().registerEventHandler(io.papermc.paper.plugin.lifecycle.event.types.LifecycleEvents.COMMANDS,
                // registrar 收的是"已构建"的节点，不是 builder
                event -> event.registrar().register(AuthCommand.build(this).build(),
                        "MikuAuth 管理命令", java.util.List.of("mauth")));

        // 过期审计清理：低频任务，走异步调度器（Folia 兼容）
        getServer().getAsyncScheduler().runAtFixedRate(this, task -> {
            purgeAudit();
            gate.tick();
        }, 5L, 60L, java.util.concurrent.TimeUnit.MINUTES);

        getLogger().info("v" + getPluginMeta().getVersion()
                + " 已加载 —— 进服前认证已启用（配置阶段对话框；客户端需 1.21.6+）");
        getLogger().info("数据库: " + config.databaseType()
                + " / " + config.databaseFile() + "（与代理端共用同一套账号表）");
    }

    @Override
    public void onDisable() {
        if (store != null) {
            store.close();
        }
    }

    /** 重载配置与语言文件（数据库连接不复用，改连接参数需重启）。 */
    public void reload() {
        reloadConfig();
        config = new PaperConfig(this);
        messages.reload();
    }

    private void purgeAudit() {
        int days = config.auditRetainDays();
        if (!config.auditEnabled() || days <= 0) {
            return;
        }
        long cutoff = System.currentTimeMillis() - days * 24L * 60 * 60 * 1000;
        store.purgeAudit(cutoff);
    }

    PaperConfig config() {
        return config;
    }

    Messages messages() {
        return messages;
    }

    Store store() {
        return store;
    }

    PreJoinGate gate() {
        return gate;
    }
}
