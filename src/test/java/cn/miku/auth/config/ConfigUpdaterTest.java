package cn.miku.auth.config;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 配置增量合并测试。
 *
 * <p>核心用例使用<b>真实的 2.1.2 配置文件</b>作为样本（{@code legacy-config-2.1.2.yml}，
 * 由老版本实际生成），验证升级后新增的配置段能被正确补进服主的文件里 ——
 * 这正是"新增功能但配置文件里看不到"这个问题的回归防线。
 *
 * <p>断言以<b>语义</b>为主（把合并结果解析成 Map 再查结构），而不是比对文本，
 * 这样重构注释与排版不会误报。
 */
class ConfigUpdaterTest {

    private static final String DEFAULT_CONFIG = "/config.yml";

    @TempDir
    Path tempDir;

    private static String resource(String name) throws Exception {
        try (InputStream input = ConfigUpdaterTest.class.getResourceAsStream(name)) {
            assertNotNull(input, "测试资源缺失: " + name);
            return new String(input.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> parse(Path file) throws Exception {
        Object loaded = new Yaml(new SafeConstructor(new LoaderOptions()))
                .load(Files.readString(file, StandardCharsets.UTF_8));
        return (Map<String, Object>) loaded;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> section(Map<String, Object> root, String key) {
        Object value = root.get(key);
        assertTrue(value instanceof Map, "缺少配置段: " + key);
        return (Map<String, Object>) value;
    }

    private Path writeLegacyConfig() throws Exception {
        Path file = tempDir.resolve("config.yml");
        Files.writeString(file, resource("/legacy-config-2.1.2.yml"), StandardCharsets.UTF_8);
        return file;
    }

    // ---------------------------------------------------------------------
    // 核心：真实旧版配置的升级
    // ---------------------------------------------------------------------

    @Test
    void legacyConfigGetsAllNewSections() throws Exception {
        Path file = writeLegacyConfig();
        ConfigUpdater.Result result = ConfigUpdater.merge(file, DEFAULT_CONFIG, null);

        assertTrue(result.changed(), "应当补充了新增配置项");
        assertTrue(result.added().contains("security"), "应补充 security 段: " + result.added());
        assertTrue(result.added().contains("database.mariadb"), "应补充 database.mariadb: " + result.added());
        assertTrue(result.added().contains("commands.changepassword-aliases"),
                "应补充 commands.changepassword-aliases: " + result.added());

        Map<String, Object> parsed = parse(file);
        Map<String, Object> security = section(parsed, "security");
        assertEquals(5, security.get("max-failures"));
        assertEquals(15, security.get("failure-window-minutes"));
        assertEquals(5, security.get("lockout-minutes"));

        // 新增的嵌套子项必须落在 database 段里（而不是变成顶层键）
        Map<String, Object> database = section(parsed, "database");
        Map<String, Object> mariadb = section(database, "mariadb");
        assertEquals("127.0.0.1", mariadb.get("host"));
        assertEquals(3306, mariadb.get("port"));
        assertEquals(6, mariadb.get("pool-size"));
        assertEquals("disable", mariadb.get("ssl-mode"));

        // 同理，别名必须落在 commands 段里
        Map<String, Object> commands = section(parsed, "commands");
        assertEquals(java.util.List.of("cp", "changepw"), commands.get("changepassword-aliases"));
    }

    @Test
    void existingValuesAndSectionsArePreserved() throws Exception {
        Path file = tempDir.resolve("config.yml");
        Files.writeString(file, """
                # 我自己的配置
                server:
                  auth-server: "myauth"
                  fallback-server: "mylobby"

                premium:
                  timeout-millis: 8000

                my-custom-section:
                  keep-me: true
                """, StandardCharsets.UTF_8);

        ConfigUpdater.merge(file, DEFAULT_CONFIG, null);
        Map<String, Object> parsed = parse(file);

        // 用户改过的值必须原样保留
        Map<String, Object> server = section(parsed, "server");
        assertEquals("myauth", server.get("auth-server"));
        assertEquals("mylobby", server.get("fallback-server"));
        assertEquals(8000, section(parsed, "premium").get("timeout-millis"));
        // 用户自定义的段落也不能被动
        assertEquals(Boolean.TRUE, section(parsed, "my-custom-section").get("keep-me"));
        // 同时新增项也补上了
        assertTrue(parsed.containsKey("security"));
        // 已被移除的旧段落（如 device）不应再被写回
        assertFalse(parsed.containsKey("device"));
    }

    @Test
    void legacySessionSectionIsLeftUntouched() throws Exception {
        Path file = writeLegacyConfig();
        ConfigUpdater.merge(file, DEFAULT_CONFIG, null);

        // 已被移除的旧 session 段不删除（只增不减），避免动到服主的文件内容
        assertTrue(parse(file).containsKey("session"));
        assertTrue(Files.readString(file, StandardCharsets.UTF_8).contains("session:"),
                "旧段落应保留，由服主自行决定是否删除");
    }

    @Test
    void commentsOfExistingLinesAreNotLost() throws Exception {
        Path file = writeLegacyConfig();
        String before = Files.readString(file, StandardCharsets.UTF_8);
        ConfigUpdater.merge(file, DEFAULT_CONFIG, null);
        String after = Files.readString(file, StandardCharsets.UTF_8);

        // 原有内容必须逐行原样存在（合并只是插入，不重排不修改）
        for (String line : before.split("\n", -1)) {
            if (line.isBlank()) {
                continue;
            }
            assertTrue(after.contains(line), "原有行丢失或被改动: " + line);
        }
    }

    @Test
    void mergeIsIdempotent() throws Exception {
        Path file = writeLegacyConfig();
        assertTrue(ConfigUpdater.merge(file, DEFAULT_CONFIG, null).changed());
        String afterFirst = Files.readString(file, StandardCharsets.UTF_8);

        ConfigUpdater.Result second = ConfigUpdater.merge(file, DEFAULT_CONFIG, null);
        assertFalse(second.changed(), "第二次合并不应再改动文件");
        assertEquals(afterFirst, Files.readString(file, StandardCharsets.UTF_8));
    }

    @Test
    void insertedEntriesKeepTemplateOrder() throws Exception {
        Path file = writeLegacyConfig();
        ConfigUpdater.merge(file, DEFAULT_CONFIG, null);
        String text = Files.readString(file, StandardCharsets.UTF_8);

        // 同一插入位置可能落多个条目：必须保持模板顺序，不能因反向插入而颠倒
        int type = text.indexOf("  type: \"sqlite\"");
        int mariadb = text.indexOf("  mariadb:");
        assertTrue(type > 0, "database.type 应被补充");
        assertTrue(mariadb > 0, "database.mariadb 应被补充");
        assertTrue(type < mariadb, "database 段内应保持模板顺序（type 在 mariadb 之前）");

        // 顶层追加的段落应落在文件末尾（原内容之后）
        int security = text.indexOf("\nsecurity:");
        int commands = text.indexOf("\ncommands:");
        assertTrue(security > 0, "应补充 security 段");
        assertTrue(commands > 0 && security > commands, "追加的顶层段落应在原有段落之后");
    }

    @Test
    void markerCommentIsAddedExactlyOnce() throws Exception {
        Path file = writeLegacyConfig();
        ConfigUpdater.merge(file, DEFAULT_CONFIG, null);
        String text = Files.readString(file, StandardCharsets.UTF_8);

        int first = text.indexOf("以下段落为 MikuAuth 新增配置项");
        assertTrue(first > 0, "追加顶层段落时应带说明注释");
        assertEquals(-1, text.indexOf("以下段落为 MikuAuth 新增配置项", first + 1),
                "说明注释只应出现一次");
    }

    // ---------------------------------------------------------------------
    // 废弃键提示
    //
    // 当前 RETIRED_KEYS 为空：唯一一个曾经的废弃键 dialog.enabled 在 2.7.0 重新成为
    // 真实开关（关闭后回到聊天栏登录），必须从表中移除——留着会让服主看到
    // "本键不再生效"的注释，而它其实已经生效。
    //
    // 下面第一个用例因此改为断言"不再标注"；后两个用例仍对废弃键机制本身做巡检。
    // ---------------------------------------------------------------------

    @Test
    void reactivatedDialogEnabledIsNoLongerMarkedRetired() throws Exception {
        // 老配置（2.1.2 样本）里就带着 dialog.enabled: true。该键现在重新生效，
        // 因此既不能被标注废弃，也不该被模板补一份（用户已经有这个键了）
        Path file = writeLegacyConfig();
        ConfigUpdater.merge(file, DEFAULT_CONFIG, null);
        String text = Files.readString(file, StandardCharsets.UTF_8);

        assertFalse(text.contains("已废弃："),
                "dialog.enabled 已重新生效，不得再插入'已废弃'注释");
        // 键本身必须原样保留，且注释不影响解析
        Map<String, Object> dialog = section(parse(file), "dialog");
        assertEquals(Boolean.TRUE, dialog.get("enabled"));
    }

    @Test
    void retiredKeyNoticeIsNotAddedWhenKeyStaysInSync() throws Exception {
        // 覆盖废弃键机制的巡检用例：用户配置已是最新版（没有需要补充的段落），
        // 且不含任何废弃键时，合并必须报告"无改动"且不写提示。
        // 注意：这里刻意不再往模板里塞 dialog.enabled —— 它现在是合法键，
        // 塞进去只会命中"用户已有该键、跳过"这条正常分支，测不出废弃键逻辑。
        Path file = tempDir.resolve("config.yml");
        Files.writeString(file, resource(DEFAULT_CONFIG).replace("\r\n", "\n"),
                StandardCharsets.UTF_8);

        ConfigUpdater.Result result = ConfigUpdater.merge(file, DEFAULT_CONFIG, null);

        assertFalse(result.changed(), "配置已是最新版时不应有任何改动");
        assertFalse(Files.readString(file, StandardCharsets.UTF_8).contains("已废弃："));
    }

    @Test
    void retiredKeyNoticeIsNotAddedForFreshConfigs() throws Exception {
        // 内置默认配置本身不含废弃键，因此全新安装不应产生任何提示
        Path file = tempDir.resolve("config.yml");
        Files.writeString(file, resource(DEFAULT_CONFIG).replace("\r\n", "\n"), StandardCharsets.UTF_8);

        assertFalse(ConfigUpdater.merge(file, DEFAULT_CONFIG, null).changed());
        assertFalse(Files.readString(file, StandardCharsets.UTF_8).contains("已废弃："));
    }

    // ---------------------------------------------------------------------
    // 安全约束
    // ---------------------------------------------------------------------

    @Test
    void crlfFilesAreHandled() throws Exception {
        // 服主用 Windows 记事本编辑配置会产生 CRLF；若解析不容忍行尾 \r，
        // 合并会静默失效（模板一个键都读不出来）。这是实际踩到过的回归点。
        Path file = tempDir.resolve("config.yml");
        Files.writeString(file, resource("/legacy-config-2.1.2.yml").replace("\n", "\r\n"),
                StandardCharsets.UTF_8);

        ConfigUpdater.Result result = ConfigUpdater.merge(file, DEFAULT_CONFIG, null);

        assertTrue(result.changed(), "CRLF 文件也应能正常合并");
        assertTrue(result.added().contains("security"), "应补充 security: " + result.added());
        assertTrue(parse(file).containsKey("security"));

        // 输出应保持用户文件原有的 CRLF 风格，不要混入 LF
        String merged = Files.readString(file, StandardCharsets.UTF_8);
        assertTrue(merged.contains("\r\n"), "应保持 CRLF 换行");
        assertEquals(-1, merged.replace("\r\n", "").indexOf('\n'), "不应出现孤立的 LF");
    }

    @Test
    void invalidYamlIsNeverTouched() throws Exception {
        Path file = tempDir.resolve("config.yml");
        String broken = "server:\n  auth-server: \"auth\"\n   bad-indent: oops\n";
        Files.writeString(file, broken, StandardCharsets.UTF_8);

        ConfigUpdater.Result result = ConfigUpdater.merge(file, DEFAULT_CONFIG, null);

        assertFalse(result.changed());
        assertEquals(broken, Files.readString(file, StandardCharsets.UTF_8), "语法有误的文件必须原样保留");
    }

    @Test
    void emptyFileIsNeverTouched() throws Exception {
        Path file = tempDir.resolve("config.yml");
        Files.writeString(file, "   \n", StandardCharsets.UTF_8);
        assertFalse(ConfigUpdater.merge(file, DEFAULT_CONFIG, null).changed());
        assertEquals("   \n", Files.readString(file, StandardCharsets.UTF_8));
    }

    @Test
    void backupIsCreatedOnce() throws Exception {
        Path file = writeLegacyConfig();
        String original = Files.readString(file, StandardCharsets.UTF_8);
        ConfigUpdater.merge(file, DEFAULT_CONFIG, null);

        Path backup = tempDir.resolve("config.yml.bak");
        assertTrue(Files.exists(backup), "首次修改前应留备份");
        assertEquals(original, Files.readString(backup, StandardCharsets.UTF_8));

        // 再次合并（无改动）不应覆盖备份
        ConfigUpdater.merge(file, DEFAULT_CONFIG, null);
        assertEquals(original, Files.readString(backup, StandardCharsets.UTF_8));
    }

    // ---------------------------------------------------------------------
    // messages.yml
    // ---------------------------------------------------------------------

    @Test
    void legacyMessagesGetNewKeys() throws Exception {
        Path file = tempDir.resolve("messages.yml");
        Files.writeString(file, resource("/legacy-messages-2.1.2.yml"), StandardCharsets.UTF_8);

        ConfigUpdater.Result result = ConfigUpdater.merge(file, "/messages.yml", null);

        assertTrue(result.changed());
        assertTrue(result.added().contains("changepassword"), "应补充 changepassword 段: " + result.added());
        assertTrue(result.added().contains("error.locked"), "应补充 error.locked: " + result.added());

        Map<String, Object> parsed = parse(file);
        Map<String, Object> changePassword = section(parsed, "changepassword");
        assertNotNull(changePassword.get("usage"));
        assertNotNull(changePassword.get("success"));

        // 新增文案必须落在正确的父段下
        assertNotNull(section(parsed, "changepassword").get("wrong-locked"));
        Map<String, Object> auto = section(section(parsed, "auth"), "auto");
        assertNotNull(auto.get("session"), "session 文案应位于 auth.auto 之下");
        // 原有文案保持
        assertNotNull(section(parsed, "admin").get("help"));
    }
}
