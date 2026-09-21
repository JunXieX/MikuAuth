package cn.miku.auth.security;

import at.favre.lib.crypto.bcrypt.BCrypt;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;

/**
 * 密码校验与升级（支持从其他登录插件迁移过来的历史哈希）。
 *
 * <p>本插件自身只产生 <b>BCrypt</b> 哈希，但迁移来的账号可能带着别的算法：
 * <ul>
 *   <li><b>AuthMe</b>：{@code $SHA$salt$hash}（{@code sha256(sha256(密码的十六进制) + salt)}）、
 *       {@code $SHA512$salt$hash}（同构）、老版本的 32 位 MD5；</li>
 *   <li><b>LibreLogin / LimboAuth</b>：默认均为 BCrypt（直接兼容），
 *       若其 {@code algo} 列为其他算法则不迁移密码（见 {@link #detect}）。</li>
 * </ul>
 *
 * <p><b>渐进升级</b>：校验成功后调用 {@link #needsUpgrade} 判断是否为旧算法，
 * 是则立即用 BCrypt 重写——玩家无感，但哈希强度随首次登录自动提升到当前标准，
 * 无需强制全员重置密码。
 *
 * <p>所有比对采用<b>常量时间</b>比较，避免通过响应时间侧信道逐字节猜解哈希。
 */
public final class PasswordHasher {

    /** 由存储串格式识别出的算法。 */
    public enum Algorithm {
        BCRYPT,
        AUTHME_SHA256,
        AUTHME_SHA512,
        AUTHME_MD5,
        /** 不认识的格式（例如 Argon2、或 LibreLogin 的自定义 algo）：不能校验。 */
        UNKNOWN
    }

    private static final String PREFIX_SHA256 = "$SHA$";
    private static final String PREFIX_SHA512 = "$SHA512$";

    private PasswordHasher() {
    }

    // ---------------------------------------------------------------------
    // 识别
    // ---------------------------------------------------------------------

    /** 按前缀/形态识别算法（不做任何 IO）。 */
    public static Algorithm detect(String stored) {
        if (stored == null || stored.isEmpty()) {
            return Algorithm.UNKNOWN;
        }
        if (stored.startsWith("$2a$") || stored.startsWith("$2b$") || stored.startsWith("$2y$")) {
            return Algorithm.BCRYPT;
        }
        if (stored.startsWith(PREFIX_SHA256)) {
            return Algorithm.AUTHME_SHA256;
        }
        if (stored.startsWith(PREFIX_SHA512)) {
            return Algorithm.AUTHME_SHA512;
        }
        // AuthMe 早期版本用无盐 MD5：32 位十六进制
        if (stored.length() == 32 && stored.chars()
                .allMatch(c -> (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
            return Algorithm.AUTHME_MD5;
        }
        return Algorithm.UNKNOWN;
    }

    /** 该哈希是否应当在校验成功后升级为 BCrypt。 */
    public static boolean needsUpgrade(String stored) {
        return detect(stored) != Algorithm.BCRYPT;
    }

    // ---------------------------------------------------------------------
    // 校验
    // ---------------------------------------------------------------------

    /**
     * 校验密码。
     *
     * @param password 明文密码
     * @param stored   数据库中的哈希（可能是 BCrypt，也可能是迁移来的旧格式）
     * @return 是否匹配；格式无法识别时返回 false（fail-closed）
     */
    public static boolean verify(String password, String stored) {
        if (password == null || stored == null) {
            return false;
        }
        return switch (detect(stored)) {
            case BCRYPT -> BCrypt.verifyer().verify(password.toCharArray(), stored).verified;
            case AUTHME_SHA256 -> verifyAuthMe(password, stored, PREFIX_SHA256, "SHA-256");
            case AUTHME_SHA512 -> verifyAuthMe(password, stored, PREFIX_SHA512, "SHA-512");
            case AUTHME_MD5 -> constantTimeEquals(hex(md5(password)), stored.toLowerCase(Locale.ROOT));
            case UNKNOWN -> false;
        };
    }

    /**
     * AuthMe 的加盐二次哈希：{@code algo( algo(密码) + salt )}，
     * 其中内层结果先转成<b>小写十六进制字符串</b>再与 salt 拼接。
     */
    private static boolean verifyAuthMe(String password, String stored, String prefix, String algo) {
        String body = stored.substring(prefix.length());
        int split = body.indexOf('$');
        if (split <= 0 || split == body.length() - 1) {
            return false;
        }
        String salt = body.substring(0, split);
        String expected = body.substring(split + 1);
        String innerHex = hex(digest(password, algo));
        String computed = hex(digest(innerHex + salt, algo));
        return constantTimeEquals(computed, expected);
    }

    /** 生成新的 BCrypt 哈希（迁移时若源密码无法校验也可用它重置）。 */
    public static String hash(String password, int cost) {
        return BCrypt.withDefaults().hashToString(cost, password.toCharArray());
    }

    // ---------------------------------------------------------------------
    // 摘要原语
    // ---------------------------------------------------------------------

    private static byte[] digest(String input, String algorithm) {
        try {
            return MessageDigest.getInstance(algorithm).digest(input.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("JDK 缺少摘要算法 " + algorithm, e);
        }
    }

    private static byte[] md5(String input) {
        return digest(input, "MD5");
    }

    /** 字节数组 → 小写十六进制。 */
    private static String hex(byte[] bytes) {
        StringBuilder builder = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            builder.append(Character.forDigit((b >> 4) & 0xF, 16));
            builder.append(Character.forDigit(b & 0xF, 16));
        }
        return builder.toString();
    }

    /** 常量时间字符串比较。 */
    private static boolean constantTimeEquals(String a, String b) {
        return MessageDigest.isEqual(
                a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }
}
