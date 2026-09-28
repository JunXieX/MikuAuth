package cn.miku.auth.security;

import at.favre.lib.crypto.bcrypt.BCrypt;
import at.favre.lib.crypto.bcrypt.LongPasswordStrategies;

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
            case BCRYPT -> verifyBcrypt(password, stored);
            case AUTHME_SHA256 -> verifyAuthMe(password, stored, PREFIX_SHA256, "SHA-256");
            case AUTHME_SHA512 -> verifyAuthMe(password, stored, PREFIX_SHA512, "SHA-512");
            case AUTHME_MD5 -> constantTimeEquals(hex(md5(password)), stored.toLowerCase(Locale.ROOT));
            case UNKNOWN -> false;
        };
    }

    /**
     * 校验 BCrypt 哈希。
     *
     * <p>favre 实现默认是 <b>strict</b> 策略：密码超过 72 <b>字节</b> 会抛
     * {@code IllegalArgumentException} 而不是静默截断（这个默认是安全的，本插件自己产生的
     * 哈希也不会超限，因为 {@link PasswordPolicy} 已按字节数拦下）。
     *
     * <p>但迁移来源（bcryptjs、LimboAuth 等）普遍按"截断到 72 字节"实现：用 strict 校验这些
     * 账号会<b>永远失败</b>——能建号却登不进，且每次都被计为密码错误、可能触发临时封禁。
     * 因此这里先严格校验，抛异常时再按截断重试一次，两种历史实现都能通过。
     */
    private static boolean verifyBcrypt(String password, String stored) {
        try {
            return BCrypt.verifyer().verify(password.toCharArray(), stored).verified;
        } catch (IllegalArgumentException tooLongByStrictPolicy) {
            return BCrypt.verifyer(BCrypt.Version.VERSION_2A,
                    LongPasswordStrategies.truncate(BCrypt.Version.VERSION_2A))
                    .verify(password.toCharArray(), stored).verified;
        }
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
        // 十六进制大小写不敏感：MD5 分支一直是这么做的，SHA 分支早期漏了这一层，
        // 遇到大写十六进制的历史哈希会永远校验失败（能建号却登不进）
        String expected = body.substring(split + 1).toLowerCase(Locale.ROOT);
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
