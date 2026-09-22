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
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 增量合并的"边界输入"回归测试。
 *
 * <p>这些用例对应 2026-09-22 代码审查实测出的真实缺陷：合并逻辑用正则 + "缩进 ÷ 2"
 * 推导键路径，遇到<b>带引号的键</b>、<b>首行 BOM</b>、<b>非 2 空格缩进</b>时会漏检键，
 * 于是把模板默认值追加进去 —— 而 SnakeYAML 默认"重复键后者胜"，结果是
 * <b>用户显式设置的值被静默覆盖</b>（实测：用户写 {@code "enabled": false} 合并后变 true；
 * 用户改过的认证服名被改回默认值，下次启动会因"认证服不存在"直接停用插件）。
 *
 * <p>因此断言重点不是"有没有写入"，而是<b>合并后解析出来的值必须仍等于用户写的值</b>。
 */
class ConfigUpdaterRobustnessTest {

    private static final String RES = "/config.yml";

    @TempDir
    Path tempDir;

    private static String template() throws Exception {
        try (InputStream input = ConfigUpdaterRobustnessTest.class.getResourceAsStream(RES)) {
            return new String(input.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    /** 写入用户文件并执行合并，返回合并后的全文。 */
    private String merge(String userText) throws Exception {
        Path file = tempDir.resolve("config.yml");
        Files.writeString(file, userText, StandardCharsets.UTF_8);
        ConfigUpdater.merge(file, RES, null);
        return Files.readString(file, StandardCharsets.UTF_8);
    }

    @SuppressWarnings("unchecked")
    private static Object value(String text, String path) {
        Map<String, Object> root = (Map<String, Object>) new Yaml(
                new SafeConstructor(new LoaderOptions())).load(text);
        Object current = root;
        for (String part : path.split("\\.")) {
            if (!(current instanceof Map<?, ?> map)) {
                return null;
            }
            current = map.get(part);
        }
        return current;
    }

    private static int count(String text, String needle) {
        int n = 0;
        int i = 0;
        while ((i = text.indexOf(needle, i)) >= 0) {
            n++;
            i += needle.length();
        }
        return n;
    }

    @Test
    void quotedKeyDoesNotLetTemplateDefaultOverrideUserValue() throws Exception {
        // 用户把正版验证关掉，但键写成带引号的形式（YAML 合法写法）
        String user = template().replace("  enabled: true", "  \"enabled\": false");
        assertTrue(user.contains("\"enabled\": false"), "用例前提：模板里应能找到该键并改写");

        String merged = merge(user);

        assertEquals(Boolean.FALSE, value(merged, "premium.enabled"),
                "带引号的键被漏检时，模板默认值会被追加进来并覆盖用户设置（重复键后者胜）");
    }

    @Test
    void fourSpaceIndentationStillGetsNewKeys() throws Exception {
        // 用户被编辑器重排成 4 空格缩进，并缺一个新增配置项
        String user = template()
                .replace("  backend-kick-file: \"backend-kicks.log\"\n", "")
                .replace("\n  ", "\n    ");
        Path file = tempDir.resolve("config.yml");
        Files.writeString(file, user, StandardCharsets.UTF_8);

        ConfigUpdater.Result result = ConfigUpdater.merge(file, RES, null);
        String merged = Files.readString(file, StandardCharsets.UTF_8);

        assertTrue(result.added().contains("audit.backend-kick-file"),
                "4 空格缩进的文件也应能补进新配置项，实际新增: " + result.added());
        assertTrue(merged.contains("backend-kick-file"), "新键必须真的写进文件");
        assertEquals("backend-kicks.log", value(merged, "audit.backend-kick-file"));
    }

    @Test
    void bomOnFirstKeyDoesNotDuplicateSection() throws Exception {
        // 首行就是键（用户删掉了文件开头的注释块）且带 UTF-8 BOM：
        // 该键会被正则漏检，导致整个 server 段被重复追加
        String withoutHead = template().replaceAll("\\A(?:(?:#.*)?\\r?\\n)+", "")
                .replace("auth-server: \"auth\"", "auth-server: \"myauth\"");
        String user = "\uFEFF" + withoutHead;
        assertTrue(withoutHead.startsWith("server:"), "用例前提：首行应为键");

        String merged = merge(user);

        assertEquals(1, count(merged, "auth-server:"), "同一键不应出现两次（重复追加会让默认值覆盖用户值）");
        assertEquals("myauth", value(merged, "server.auth-server"), "用户改过的认证服名必须保留");
    }

    @Test
    void mergeIsIdempotentForFourSpaceFiles() throws Exception {
        String user = template()
                .replace("  backend-kick-file: \"backend-kicks.log\"\n", "")
                .replace("\n  ", "\n    ");
        Path file = tempDir.resolve("config.yml");
        Files.writeString(file, user, StandardCharsets.UTF_8);

        ConfigUpdater.Result first = ConfigUpdater.merge(file, RES, null);
        String afterFirst = Files.readString(file, StandardCharsets.UTF_8);
        ConfigUpdater.Result second = ConfigUpdater.merge(file, RES, null);
        String afterSecond = Files.readString(file, StandardCharsets.UTF_8);

        assertTrue(first.changed());
        assertFalse(second.changed(), "第二次合并不应再有改动（幂等）");
        assertEquals(afterFirst, afterSecond);
    }
}
