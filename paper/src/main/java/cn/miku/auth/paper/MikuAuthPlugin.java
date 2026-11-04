package cn.miku.auth.paper;

import cn.miku.auth.audit.AuditLogger;
import cn.miku.auth.config.MikuConfig;
import cn.miku.auth.config.MikuMessages;
import cn.miku.auth.database.DatabaseManager;
import cn.miku.auth.security.LoginThrottle;
import cn.miku.auth.util.LogSink;
import io.papermc.paper.plugin.lifecycle.event.types.LifecycleEvents;
import org.bukkit.plugin.java.JavaPlugin;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.SQLException;
import java.util.concurrent.TimeUnit;

/**
 * MikuAuth-Paper 主类。
 *
 * <p>本版本只实现一种登录模式：<b>进服前认证</b>。玩家停在服务端的配置阶段
 * （画面是"加载地形"、尚未进入世界）时由原生对话框完成注册/登录，
 * 通过之后连接才继续、玩家才真正进入世界。会话判定见 {@link PreJoinGate}。
 *
 * <p><b>与代理端共用什么</b>：密码哈希与策略（{@code :common} 的
 * {@code PasswordHasher} / {@code PasswordPolicy}）、失败计数（{@code LoginThrottle}）、
 * 数据访问与建表（{@code DatabaseManager}）、配置与文本（{@code MikuConfig} /
 * {@code MikuMessages} / {@code YamlStore}）、离线 UUID（{@code UuidUtil}）全部是同一份代码，
 * 因此两端指向同一个账号库时行为完全一致，也不会出现"这边改了那边没改"的漂移。
 *
 * <p>本模块自己只保留纸上独有的东西：配置阶段闸门、原生对话框构建、Brigadier 命令、
 * 以及把 {@code java.util.logging} 接到公共层日志口（{@link JulLogSink}）。
 */
public final class MikuAuthPlugin extends JavaPlugin {

    private LogSink sink;
    private Path dataDirectory;
    private MikuConfig config;
    private MikuMessages messages;
    private DatabaseManager database;
    private AuditLogger audit;
    private LoginThrottle throttle;
    private PreJoinGate gate;

    @Override
    public void onEnable() {
        this.sink = JulLogSink.of(getLogger());
        this.dataDirectory = getDataFolder().toPath();
        this.config = new MikuConfig();
        this.messages = new MikuMessages();

        try {
            migrateLegacyDatabaseFile();
            config.load(dataDirectory, sink);
            messages.load(dataDirectory, sink);
            this.database = new DatabaseManager(dataDirectory, config, sink);
        } catch (IOException | SQLException | RuntimeException e) {
            getLogger().severe("初始化失败: " + e);
            getServer().getPluginManager().disablePlugin(this);
            return;
        }

        this.audit = new AuditLogger(database, config, sink);
        this.throttle = new LoginThrottle(config, sink);
        this.gate = new PreJoinGate(this);
        getServer().getPluginManager().registerEvents(gate, this);

        // 管理命令（Brigadier）：/mikuauth reload|unlock|accounts|audit
        getLifecycleManager().registerEventHandler(LifecycleEvents.COMMANDS,
                event -> event.registrar().register(AuthCommand.build(this).build(),
                        "MikuAuth 管理命令", java.util.List.of("mauth")));

        // 过期审计清理 + 失败计数清理：低频任务，走异步调度器（Folia 兼容）
        getServer().getAsyncScheduler().runAtFixedRate(this, task -> {
            audit.purgeExpired();
            throttle.purge();
        }, 5L, 60L, TimeUnit.MINUTES);

        getLogger().info("v" + getPluginMeta().getVersion()
                + " 已加载 —— 进服前认证已启用（配置阶段对话框；客户端需 1.21.6+）");
        getLogger().info("数据库: " + config.databaseType() + " / " + config.databaseFile()
                + "（与代理端共用同一套账号表）");
    }

    @Override
    public void onDisable() {
        if (database != null) {
            database.close();
        }
    }

    /** 重载配置与语言文件（数据库连接不复用，改连接参数需重启）。 */
    public void reload() {
        try {
            config.load(dataDirectory, sink);
            messages.load(dataDirectory, sink);
        } catch (IOException e) {
            getLogger().warning("配置重载失败（继续使用内存中的旧值）: " + e);
        }
    }

    /**
     * 旧版数据库文件名迁移。
     *
     * <p>3.9.0 起纸端与代理端共用同一套配置项，数据库文件名改由 {@code database.file} 决定
     * （默认 {@code database.db}）。旧版纸端写死的是 {@code auth.db}；不做这一步，
     * 升级后插件会新建一个空库，服主看到的现象就是"账号全没了"。
     */
    private void migrateLegacyDatabaseFile() {
        Path legacy = dataDirectory.resolve("auth.db");
        Path current = dataDirectory.resolve("database.db");
        if (Files.notExists(legacy) || Files.exists(current)) {
            return;
        }
        try {
            Files.move(legacy, current);
            for (String suffix : new String[]{"-wal", "-shm"}) {
                Path sidecar = dataDirectory.resolve("auth.db" + suffix);
                if (Files.exists(sidecar)) {
                    Files.move(sidecar, dataDirectory.resolve("database.db" + suffix));
                }
            }
            getLogger().info("已把旧版数据库 auth.db 迁移为 database.db（账号数据保持不变）");
        } catch (IOException e) {
            getLogger().warning("旧版数据库迁移失败，将按新文件名新建库（旧文件仍保留为 auth.db）: " + e);
        }
    }

    LogSink log() {
        return sink;
    }

    MikuConfig config() {
        return config;
    }

    MikuMessages messages() {
        return messages;
    }

    DatabaseManager db() {
        return database;
    }

    AuditLogger audit() {
        return audit;
    }

    LoginThrottle throttle() {
        return throttle;
    }

    PreJoinGate gate() {
        return gate;
    }
}
