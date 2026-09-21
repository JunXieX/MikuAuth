package cn.miku.auth.security;

import org.junit.jupiter.api.Test;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 密码校验器的单元测试。
 *
 * <p>AuthMe 的两组向量来自公开的真实哈希样例（社区文档/issue 中给出的
 * 密码—哈希对照），因此这些用例同时验证了"我们算出来的结果与其他实现一致"，
 * 而不只是"自己跟自己一致"——这是迁移功能能不能真正落地的关键。
 */
class PasswordHasherTest {

    /** 真实样例：密码 pantof，AuthMe 存储格式。 */
    private static final String AUTHME_SHA256_PANTOF =
            "$SHA$c7dedf5a36c4a343$05ae3239eee683872ef1cc9096777bf4b1a72a179709efc17d8bf1603b082065";

    /** 真实样例：密码 ejemplo。 */
    private static final String AUTHME_SHA256_EJEMPLO =
            "$SHA$a1f9d6d409f03e2c$fe742523771dfaefa7c4e164720966442d54d3b887a9d953784d1cc5e234b447";

    // ---------------------------------------------------------------------
    // 算法识别
    // ---------------------------------------------------------------------

    @Test
    void detectsBcryptVariants() {
        assertEquals(PasswordHasher.Algorithm.BCRYPT,
                PasswordHasher.detect("$2a$10$abcdefghijklmnopqrstuv"));
        assertEquals(PasswordHasher.Algorithm.BCRYPT,
                PasswordHasher.detect("$2b$10$abcdefghijklmnopqrstuv"));
        assertEquals(PasswordHasher.Algorithm.BCRYPT,
                PasswordHasher.detect("$2y$10$abcdefghijklmnopqrstuv"));
    }

    @Test
    void detectsAuthMeFormats() {
        assertEquals(PasswordHasher.Algorithm.AUTHME_SHA256, PasswordHasher.detect(AUTHME_SHA256_PANTOF));
        assertEquals(PasswordHasher.Algorithm.AUTHME_SHA512,
                PasswordHasher.detect("$SHA512$c7dedf5a36c4a343$deadbeef"));
        assertEquals(PasswordHasher.Algorithm.AUTHME_MD5,
                PasswordHasher.detect("25d55ad283aa400af464c76d713c07ad"));
    }

    @Test
    void unknownFormatIsReportedAsUnknown() {
        // LibreLogin 若使用 Argon2 等本插件不支持的算法，迁移时应被识别为"不可校验"
        assertEquals(PasswordHasher.Algorithm.UNKNOWN,
                PasswordHasher.detect("$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA"));
        assertEquals(PasswordHasher.Algorithm.UNKNOWN, PasswordHasher.detect(""));
        assertEquals(PasswordHasher.Algorithm.UNKNOWN, PasswordHasher.detect(null));
    }

    // ---------------------------------------------------------------------
    // AuthMe 兼容性（与其他实现的互操作性）
    // ---------------------------------------------------------------------

    @Test
    void verifiesRealAuthMeSha256Vectors() {
        assertTrue(PasswordHasher.verify("pantof", AUTHME_SHA256_PANTOF),
                "必须能校验 AuthMe 的 $SHA$ 格式，否则迁移过来的玩家全部无法登录");
        assertTrue(PasswordHasher.verify("ejemplo", AUTHME_SHA256_EJEMPLO));
    }

    @Test
    void rejectsWrongPasswordForAuthMeHash() {
        assertFalse(PasswordHasher.verify("pantof1", AUTHME_SHA256_PANTOF));
        assertFalse(PasswordHasher.verify("Pantof", AUTHME_SHA256_PANTOF), "密码区分大小写");
        assertFalse(PasswordHasher.verify("", AUTHME_SHA256_PANTOF));
    }

    @Test
    void rejectsMalformedAuthMeHashWithoutThrowing() {
        assertFalse(PasswordHasher.verify("pantof", "$SHA$nosalt"));
        assertFalse(PasswordHasher.verify("pantof", "$SHA$salt$"));
        assertFalse(PasswordHasher.verify("pantof", "$SHA$"));
    }

    @Test
    void verifiesAuthMeMd5() {
        // MD5("12345678") 的常见已知值
        assertTrue(PasswordHasher.verify("12345678", "25d55ad283aa400af464c76d713c07ad"));
        assertTrue(PasswordHasher.verify("12345678", "25D55AD283AA400AF464C76D713C07AD"),
                "MD5 比较应大小写不敏感（不同实现的十六进制大小写不同）");
        assertFalse(PasswordHasher.verify("1234567", "25d55ad283aa400af464c76d713c07ad"));
    }

    @Test
    void verifiesSelfGeneratedSha512() throws NoSuchAlgorithmException {
        // 自造一个 $SHA512$ 向量，验证同构实现对另一种摘要算法也成立
        String salt = "0123456789abcdef";
        String inner = hex(MessageDigest.getInstance("SHA-512").digest("secret".getBytes(StandardCharsets.UTF_8)));
        String outer = hex(MessageDigest.getInstance("SHA-512")
                .digest((inner + salt).getBytes(StandardCharsets.UTF_8)));

        assertTrue(PasswordHasher.verify("secret", "$SHA512$" + salt + "$" + outer));
        assertFalse(PasswordHasher.verify("secret2", "$SHA512$" + salt + "$" + outer));
    }

    // ---------------------------------------------------------------------
    // BCrypt 与自动升级
    // ---------------------------------------------------------------------

    @Test
    void verifiesOwnBcryptHash() {
        String hash = PasswordHasher.hash("correct horse", 10);

        assertTrue(PasswordHasher.verify("correct horse", hash));
        assertFalse(PasswordHasher.verify("wrong horse", hash));
    }

    @Test
    void bcryptHashesAreSaltedIndependently() {
        String first = PasswordHasher.hash("same-password", 10);
        String second = PasswordHasher.hash("same-password", 10);

        assertFalse(first.equals(second), "相同密码每次也应产生不同哈希（随机盐）");
        assertTrue(PasswordHasher.verify("same-password", first));
        assertTrue(PasswordHasher.verify("same-password", second));
    }

    @Test
    void onlyBcryptDoesNotNeedUpgrade() {
        assertFalse(PasswordHasher.needsUpgrade(PasswordHasher.hash("x", 4)), "BCrypt 无需升级");
        assertTrue(PasswordHasher.needsUpgrade(AUTHME_SHA256_PANTOF),
                "迁移来的 AuthMe 哈希应在首次成功登录后升级为 BCrypt");
        assertTrue(PasswordHasher.needsUpgrade("25d55ad283aa400af464c76d713c07ad"));
    }

    @Test
    void unknownAlgorithmNeverVerifies() {
        // fail-closed：认不出的算法一律判失败，绝不放行
        assertFalse(PasswordHasher.verify("whatever", "$argon2id$v=19$m=65536$c2FsdA$aGFzaA"));
    }

    private static String hex(byte[] bytes) {
        StringBuilder builder = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            builder.append(Character.forDigit((b >> 4) & 0xF, 16));
            builder.append(Character.forDigit(b & 0xF, 16));
        }
        return builder.toString();
    }
}
