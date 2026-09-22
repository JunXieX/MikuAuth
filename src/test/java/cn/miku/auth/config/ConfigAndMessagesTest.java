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
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 配置与语言文件测试：默认文件复制、嵌套键查找、缺键回退、数值钳制、别名读取，
 * 以及"代码引用的文本键是否都真实存在"的一致性检查。
 */
class ConfigAndMessagesTest {

    /**
     * 代码中引用的全部文本键（含由 messageKey/textKey 动态拼接的家族）。
     * 这份清单是代码与 messages.yml 之间的契约：任何一侧改名都会让本用例失败。
     */
    private static final List<String> KEYS_REFERENCED_BY_CODE = List.of(
            // MikuMessages.prefixed("prefix") / AdminCommand 帮助
            "prefix",
            // AuthManager.completeAuth（auth.auto.* / auth.success.* 各带 title/subtitle/chat）
            "auth.auto.premium.title", "auth.auto.premium.subtitle", "auth.auto.premium.chat",
            "auth.auto.bedrock.title", "auth.auto.bedrock.subtitle", "auth.auto.bedrock.chat",
            "auth.auto.session.title", "auth.auto.session.subtitle", "auth.auto.session.chat",
            "auth.success.login.title", "auth.success.login.subtitle", "auth.success.login.chat",
            "auth.success.register.title", "auth.success.register.subtitle", "auth.success.register.chat",
            // AuthManager.startPending + DisplayManager（login/register 各带 title/subtitle/bossbar 家族）
            "login.title", "login.subtitle", "login.bossbar", "login.bossbar-static", "login.chat-usage",
            "register.title", "register.subtitle", "register.bossbar", "register.bossbar-static",
            "register.chat-usage",
            // DialogService（base = dialog.login / dialog.register）
            "dialog.login.title", "dialog.login.body", "dialog.login.input-label",
            "dialog.login.button", "dialog.login.button-tooltip",
            "dialog.login.close-button", "dialog.login.close-button-tooltip",
            "dialog.register.title", "dialog.register.body", "dialog.register.input-label",
            "dialog.register.confirm-label", "dialog.register.button", "dialog.register.button-tooltip",
            "dialog.register.close-button", "dialog.register.close-button-tooltip",
            // AuthManager 的失败反馈（errorKey 以变量传入）
            "error.already-authed", "error.please-register", "error.please-login",
            "error.password-empty", "error.password-length", "error.password-too-long",
            "error.password-mismatch",
            "error.password-wrong", "error.password-invalid-chars", "error.password-wrong-conflict",
            "error.password-same", "error.old-password-wrong", "error.password-wrong-locked",
            "error.not-registered", "error.already-registered", "error.ip-limit",
            "error.too-fast", "error.server-busy", "error.locked",
            "error.must-authenticate", "error.players-only",
            // 玩家自助改密
            "changepassword.usage", "changepassword.success",
            "changepassword.no-password", "changepassword.wrong-locked",
            // 踢出原因
            "kick.premium-verify-failed", "kick.auth-error", "kick.name-snipe",
            "kick.auth-timeout", "kick.too-many-tries",
            // 管理命令
            "admin.usage", "admin.error",
            "admin.accounts.header", "admin.accounts.entry", "admin.accounts.not-found", "admin.accounts.no-ip",
            "admin.diagnose.header", "admin.diagnose.db-none", "admin.diagnose.db-premium",
            "admin.diagnose.db-offline", "admin.diagnose.db-offline-no-password",
            "admin.diagnose.api-disabled", "admin.diagnose.api-premium", "admin.diagnose.api-offline",
            "admin.diagnose.api-unknown", "admin.diagnose.decision-online",
            "admin.diagnose.decision-offline", "admin.diagnose.decision-deny", "admin.diagnose.conflict",
            "admin.deletepassword.success", "admin.deletepassword.not-found",
            "admin.setpassword.success", "admin.setpassword.not-found",
            "admin.unbind.success", "admin.unbind.not-found",
            "admin.unlock.success", "admin.unlock.not-found",
            "admin.limit.current", "admin.limit.set", "admin.limit.invalid",
            "admin.reload.done");

    @TempDir
    Path tempDir;

    // ---------------------------------------------------------------------
    // messages.yml
    // ---------------------------------------------------------------------

    @Test
    void defaultMessagesFileIsCopiedOnFirstLoad() throws Exception {
        MikuMessages messages = new MikuMessages();
        messages.load(tempDir, null);

        assertTrue(Files.exists(tempDir.resolve("messages.yml")), "首次加载应复制内置默认语言文件");
        assertFalse(messages.raw("prefix").equals("prefix"));
    }

    @Test
    void keysReferencedByCodeAreAllResolvable() throws Exception {
        MikuMessages messages = new MikuMessages();
        messages.load(tempDir, null);

        for (String key : KEYS_REFERENCED_BY_CODE) {
            String raw = messages.raw(key);
            assertFalse(raw.equals(key), "文本键解析失败（显示为键名本身）: " + key);
            assertFalse(raw.isBlank(), "文本键内容为空: " + key);
        }
    }

    @Test
    void everyBuiltInLeafKeyIsResolvable() throws Exception {
        // 反向覆盖：内置 messages.yml 里的每个叶子键都必须能被 MikuMessages 解析出来
        // （点分路径逐层下钻若写错，整份文案都会退化成键名字符串）
        MikuMessages messages = new MikuMessages();
        messages.load(tempDir, null);

        List<String> leaves = new ArrayList<>();
        List<String> lists = new ArrayList<>();
        collectLeaves(loadBuiltInMessages(), "", leaves, lists);

        assertTrue(leaves.size() > 60, "内置语言文件叶子键数量异常: " + leaves.size());
        for (String key : leaves) {
            String raw = messages.raw(key);
            assertFalse(raw.equals(key), "内置键无法解析: " + key);
            assertFalse(raw.isBlank(), "内置键内容为空: " + key);
        }
        for (String key : lists) {
            assertFalse(messages.rawList(key).isEmpty(), "内置列表键为空: " + key);
        }
        // admin.help 是唯一的多行列表键
        assertTrue(lists.contains("admin.help"));
    }

    @Test
    void missingKeysFallBackToBuiltInDefaults() throws Exception {
        // 用户文件只保留一段：其余键必须自动回退内置默认值（升级后无需重写用户文件）
        Files.writeString(tempDir.resolve("messages.yml"),
                "prefix: \"<gray>[自定义]</gray> \"\n", StandardCharsets.UTF_8);

        MikuMessages messages = new MikuMessages();
        messages.load(tempDir, null);

        assertTrue(messages.raw("prefix").contains("自定义"), "用户自定义值应优先生效");
        assertFalse(messages.raw("login.title").equals("login.title"), "缺失的键应回退内置默认");
    }

    @Test
    void unknownKeyReturnsKeyItself() throws Exception {
        MikuMessages messages = new MikuMessages();
        messages.load(tempDir, null);
        assertEquals("不存在的键", messages.raw("不存在的键"));
        assertTrue(messages.rawList("不存在的列表").isEmpty());
    }

    @Test
    void reloadPicksUpChanges() throws Exception {
        MikuMessages messages = new MikuMessages();
        messages.load(tempDir, null);
        String before = messages.raw("prefix");

        Files.writeString(tempDir.resolve("messages.yml"),
                "prefix: \"<gray>[重载后]</gray> \"\n", StandardCharsets.UTF_8);
        messages.load(tempDir, null);

        assertFalse(before.equals(messages.raw("prefix")), "重载后应读到新内容（查找缓存需失效）");
        assertTrue(messages.raw("prefix").contains("重载后"));
    }

    // ---------------------------------------------------------------------
    // config.yml
    // ---------------------------------------------------------------------

    @Test
    void configDefaultsAreApplied() throws Exception {
        MikuConfig config = new MikuConfig();
        config.load(tempDir, null);

        assertTrue(Files.exists(tempDir.resolve("config.yml")));
        assertEquals("auth", config.authServer());
        assertEquals("", config.fallbackServer());
        assertTrue(config.premiumEnabled());
        assertTrue(config.premiumFailClosed());
        assertEquals(3, config.maxAccountsPerIp());
        assertEquals(60, config.authTimeoutSeconds());
        assertEquals(10, config.bcryptCost());
        assertEquals(List.of("l", "log"), config.loginAliases());
        assertEquals(List.of("reg"), config.registerAliases());
    }

    @Test
    void numericValuesAreClamped() throws Exception {
        Files.writeString(tempDir.resolve("config.yml"), """
                premium:
                  timeout-millis: 999999
                registration:
                  min-password-length: 0
                  max-password-length: 999
                login:
                  bcrypt-cost: 99
                """, StandardCharsets.UTF_8);

        MikuConfig config = new MikuConfig();
        config.load(tempDir, null);

        assertEquals(30000, config.premiumTimeoutMillis());
        assertEquals(1, config.minPasswordLength());
        assertEquals(128, config.maxPasswordLength());
        assertEquals(31, config.bcryptCost());
        // 未出现在用户文件中的键继续使用内置默认
        assertEquals("auth", config.authServer());
    }

    @Test
    void aliasesAreReadFromConfigAndCached() throws Exception {
        Files.writeString(tempDir.resolve("config.yml"), """
                commands:
                  login-aliases: ["lg", "signin"]
                  register-aliases: ["rg"]
                """, StandardCharsets.UTF_8);

        MikuConfig config = new MikuConfig();
        config.load(tempDir, null);

        assertEquals(List.of("lg", "signin"), config.loginAliases());
        assertEquals(List.of("rg"), config.registerAliases());
        // 缓存列表不可变，防止调用方误改
        assertThrowsUnsupported(() -> config.loginAliases().add("x"));
    }

    @Test
    void runtimeIpLimitOverrideWins() throws Exception {
        MikuConfig config = new MikuConfig();
        config.load(tempDir, null);
        assertEquals(3, config.maxAccountsPerIp());

        config.setMaxAccountsPerIpOverride(0);
        assertEquals(0, config.maxAccountsPerIp());
        config.setMaxAccountsPerIpOverride(7);
        assertEquals(7, config.maxAccountsPerIp());
    }

    // ---------------------------------------------------------------------
    // 工具
    // ---------------------------------------------------------------------

    @SuppressWarnings("unchecked")
    private static Map<String, Object> loadBuiltInMessages() {
        try (InputStream input = ConfigAndMessagesTest.class.getResourceAsStream("/messages.yml")) {
            assertNotNull(input, "内置 messages.yml 缺失");
            return (Map<String, Object>) new Yaml(new SafeConstructor(new LoaderOptions())).load(input);
        } catch (Exception e) {
            throw new AssertionError("读取内置 messages.yml 失败", e);
        }
    }

    /** 递归收集叶子键：字符串叶子进 strings，列表叶子进 lists。 */
    private static void collectLeaves(Map<String, Object> section, String prefix,
                                      List<String> strings, List<String> lists) {
        for (Map.Entry<String, Object> entry : section.entrySet()) {
            String path = prefix.isEmpty() ? entry.getKey() : prefix + "." + entry.getKey();
            Object value = entry.getValue();
            if (value instanceof Map<?, ?> nested) {
                @SuppressWarnings("unchecked")
                Map<String, Object> cast = (Map<String, Object>) nested;
                collectLeaves(cast, path, strings, lists);
            } else if (value instanceof List<?>) {
                lists.add(path);
            } else if (value != null) {
                strings.add(path);
            }
        }
    }

    private static void assertThrowsUnsupported(Runnable action) {
        try {
            action.run();
            throw new AssertionError("应当抛出 UnsupportedOperationException");
        } catch (UnsupportedOperationException expected) {
            // 预期
        }
    }
}
