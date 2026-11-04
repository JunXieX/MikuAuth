package cn.miku.auth.config;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 登录模式与对话框提交通道的配置读取测试。
 *
 * <p>重点锁定两条"配错不能静默生效"的规则：
 * <ul>
 *   <li>{@code login.mode} 拼错时必须回落到 {@code post}（否则服主以为开了 pre，实际没开）；</li>
 *   <li>配置阶段的等待上限不允许落到 0/不限时（否则闸门可能永远不放行，玩家卡在加载地形）。</li>
 * </ul>
 */
class LoginModeConfigTest {

    @TempDir
    Path tempDir;

    private MikuConfig load(String yaml) throws Exception {
        Files.writeString(tempDir.resolve("config.yml"), yaml, StandardCharsets.UTF_8);
        MikuConfig config = new MikuConfig();
        config.load(tempDir, null);
        return config;
    }

    @Test
    void defaultModeIsPost() throws Exception {
        MikuConfig config = new MikuConfig();
        config.load(tempDir, null);

        assertEquals("post", config.loginMode(), "出厂默认必须是 post（保持 3.8.0 行为）");
        assertFalse(config.preAuthEnabled());
        assertEquals(30, config.preAuthTimeoutSeconds());
        assertTrue(config.preAuthShowCancelButton());
    }

    @Test
    void preModeIsEnabled() throws Exception {
        MikuConfig config = load("login:\n  mode: \"pre\"\n");

        assertEquals("pre", config.loginMode());
        assertTrue(config.preAuthEnabled());
    }

    @Test
    void unknownModeFallsBackToPost() throws Exception {
        MikuConfig config = load("login:\n  mode: \"prejoin\"\n");

        assertEquals("post", config.loginMode());
        assertFalse(config.preAuthEnabled());
    }

    @Test
    void preTimeoutFallsBackToGlobalTimeout() throws Exception {
        MikuConfig config = load("login:\n  timeout-seconds: 45\n  pre:\n    timeout-seconds: 0\n");

        assertEquals(45, config.preAuthTimeoutSeconds());
    }

    @Test
    void preTimeoutIsNeverZero() throws Exception {
        MikuConfig config = load("login:\n  timeout-seconds: 0\n  pre:\n    timeout-seconds: 0\n");

        assertEquals(60, config.preAuthTimeoutSeconds(),
                "配置阶段不允许「不限时」：闸门无人放行时必须有兜底上限");
    }

    @Test
    void submitChannelDefaultsToCustomAndRejectsUnknown() throws Exception {
        MikuConfig defaults = new MikuConfig();
        defaults.load(tempDir, null);
        assertEquals("custom", defaults.submitChannel(), "默认走 custom：密码不经过命令系统");

        MikuConfig typo = load("dialog:\n  submit-channel: \"cmd\"\n");
        assertEquals("custom", typo.submitChannel());

        MikuConfig command = load("dialog:\n  submit-channel: \"command\"\n");
        assertEquals("command", command.submitChannel());
    }
}
