package cn.miku.auth.security;

import cn.miku.auth.config.MikuConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 密码策略测试：长度、字符集，以及三处入口（注册 / 改密 / 管理员重置）共用同一套规则。
 */
class PasswordPolicyTest {

    @TempDir
    Path tempDir;

    private MikuConfig config;

    @BeforeEach
    void setUp() throws Exception {
        Files.writeString(tempDir.resolve("config.yml"), """
                registration:
                  min-password-length: 6
                  max-password-length: 12
                """, StandardCharsets.UTF_8);
        config = new MikuConfig();
        config.load(tempDir, null);
    }

    @Test
    void acceptsValidPassword() {
        assertNull(PasswordPolicy.check(config, "abc123"));
        assertNull(PasswordPolicy.check(config, "中文密码也可以"));
    }

    @Test
    void rejectsEmptyPassword() {
        assertEquals("error.password-empty", PasswordPolicy.check(config, null).messageKey());
        assertEquals("error.password-empty", PasswordPolicy.check(config, "").messageKey());
    }

    @Test
    void rejectsOutOfRangeLength() {
        PasswordPolicy.Violation tooShort = PasswordPolicy.check(config, "abc");
        assertEquals("error.password-length", tooShort.messageKey());
        assertEquals("6", tooShort.placeholders().get("min"));
        assertEquals("12", tooShort.placeholders().get("max"));

        assertEquals("error.password-length", PasswordPolicy.check(config, "abcdefghijklm").messageKey());
    }

    @Test
    void rejectsWhitespaceAndControlChars() {
        // 含空格的密码能注册成功但永远登不上（命令按空格分词），必须在入口拦掉
        assertEquals("error.password-invalid-chars", PasswordPolicy.check(config, "abc 123").messageKey());
        assertEquals("error.password-invalid-chars", PasswordPolicy.check(config, "abc\t123").messageKey());
        assertEquals("error.password-invalid-chars", PasswordPolicy.check(config, "abc\u0000123").messageKey());
    }

    @Test
    void hasUnsupportedCharsHandlesNull() {
        assertFalse(PasswordPolicy.hasUnsupportedChars(null));
        assertFalse(PasswordPolicy.hasUnsupportedChars("normal123"));
        assertTrue(PasswordPolicy.hasUnsupportedChars("a b"));
    }

    @Test
    void policyFollowsConfigReload() throws Exception {
        // 8 位：min 6 / max 12 下通过
        assertNull(PasswordPolicy.check(config, "abc12345"));

        Files.writeString(tempDir.resolve("config.yml"), """
                registration:
                  min-password-length: 10
                  max-password-length: 12
                """, StandardCharsets.UTF_8);
        config.load(tempDir, null);

        // 重载后 min 提高到 10，同一个密码被拒（配置查找缓存必须失效）
        assertEquals("error.password-length", PasswordPolicy.check(config, "abc12345").messageKey());
    }
}
