package cn.miku.auth.audit;

import cn.miku.auth.config.MikuConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 正版昵称冲突记录文件的测试。
 *
 * <p>这个文件是"离线客户端占用正版昵称"这一场景下**唯一的事后线索**——
 * 玩家在客户端只看到「无效会话」，服务端无法给出任何提示。因此测试重点是：
 * 该记的记得完整（昵称/IP/状态/说明），不该记的绝不记，且写入永远不抛异常。
 */
class PremiumConflictLogTest {

    @TempDir
    Path dataDirectory;

    @Test
    void writesConflictRecordWithAllFields() throws IOException {
        MikuConfig config = loadConfig("premium-conflicts.log");
        PremiumConflictLog log = new PremiumConflictLog(dataDirectory, config,
                org.slf4j.helpers.NOPLogger.NOP_LOGGER);

        log.record("JunXieX", "120.40.60.130", "玩家取消", "该昵称已确认为正版");
        log.flush();

        String content = Files.readString(dataDirectory.resolve("premium-conflicts.log"),
                StandardCharsets.UTF_8);
        assertTrue(content.contains("JunXieX"), "昵称必须记录（管理员据此联系玩家）");
        assertTrue(content.contains("120.40.60.130"), "来源 IP 必须记录（据此识别是否为同一人反复尝试）");
        assertTrue(content.contains("玩家取消"));
        assertTrue(content.contains("该昵称已确认为正版"));
        assertTrue(content.contains("#"), "文件头应包含成因与处理说明，便于日后翻看无需查代码");
        assertTrue(content.contains("unbind"), "文件头应给出处理方式");
    }

    @Test
    void appendsMultipleRecordsWithoutRepeatingHeader() throws IOException {
        MikuConfig config = loadConfig("premium-conflicts.log");
        PremiumConflictLog log = new PremiumConflictLog(dataDirectory, config,
                org.slf4j.helpers.NOPLogger.NOP_LOGGER);

        log.record("Alice", "1.1.1.1", "玩家取消", "冲突");
        log.flush();
        log.record("Bob", "2.2.2.2", "玩家取消", "冲突");
        log.flush();

        List<String> lines = Files.readAllLines(dataDirectory.resolve("premium-conflicts.log"));
        long dataLines = lines.stream().filter(line -> !line.startsWith("#")).count();
        assertEquals(2, dataLines, "两条记录都应写入");
        long headerMarks = lines.stream().filter(line -> line.startsWith("# MikuAuth")).count();
        assertEquals(1, headerMarks, "文件头只应写一次");
    }

    @Test
    void missingIpIsRenderedAsDash() throws IOException {
        MikuConfig config = loadConfig("premium-conflicts.log");
        PremiumConflictLog log = new PremiumConflictLog(dataDirectory, config,
                org.slf4j.helpers.NOPLogger.NOP_LOGGER);

        log.record("NoIp", null, "玩家取消", "冲突");
        log.flush();

        String content = Files.readString(dataDirectory.resolve("premium-conflicts.log"));
        assertTrue(content.contains("NoIp | - |"), "取不到 IP 时应显示占位符而不是 null");
    }

    @Test
    void emptyConfigDisablesLogging() throws IOException {
        MikuConfig config = loadConfig("");
        PremiumConflictLog log = new PremiumConflictLog(dataDirectory, config,
                org.slf4j.helpers.NOPLogger.NOP_LOGGER);

        assertFalse(log.enabled());
        log.record("Alice", "1.1.1.1", "玩家取消", "冲突");
        log.flush();

        assertFalse(Files.exists(dataDirectory.resolve("premium-conflicts.log")),
                "配置为空时不应创建任何文件");
    }

    @Test
    void customFileNameIsHonoured() throws IOException {
        MikuConfig config = loadConfig("logs/premium.log");
        PremiumConflictLog log = new PremiumConflictLog(dataDirectory, config,
                org.slf4j.helpers.NOPLogger.NOP_LOGGER);

        log.record("Alice", "1.1.1.1", "玩家取消", "冲突");
        log.flush();

        assertTrue(Files.exists(dataDirectory.resolve("logs/premium.log")),
                "应支持带子目录的自定义文件名，并自动创建目录");
    }

    private MikuConfig loadConfig(String fileName) throws IOException {
        Files.writeString(dataDirectory.resolve("config.yml"), """
                server:
                  auth-server: "auth"
                audit:
                  premium-conflict-file: "%s"
                """.formatted(fileName), StandardCharsets.UTF_8);
        MikuConfig config = new MikuConfig();
        config.load(dataDirectory, null);
        return config;
    }
}
