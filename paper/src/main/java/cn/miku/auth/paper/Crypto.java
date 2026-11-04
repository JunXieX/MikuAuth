package cn.miku.auth.paper;

import at.favre.lib.crypto.bcrypt.BCrypt;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

/**
 * 密码与身份工具：离线 UUID、BCrypt 哈希，以及从代理端迁移过来的历史哈希校验。
 *
 * <p>校验口径与代理端保持一致，因此同一个账号库可以被两端共用：
 * <ul>
 *   <li>本插件只产生 BCrypt（{@code $2a$/$2b$/$2y$}）；</li>
 *   <li>能读 AuthMe 的 {@code $SHA$salt$hash}、{@code $SHA512$salt$hash} 与 32 位 MD5，
 *       玩家首次登录成功后自动升级为 BCrypt。</li>
 * </ul>
 */
public final class Crypto {

    private Crypto() {
    }

    /**
     * 由昵称推导离线 UUID：MD5 版本 3，输入 {@code "OfflinePlayer:" + 昵称}。
     *
     * <p>必须与服务端给玩家分配的 UUID 完全一致，否则同一个离线玩家会被算成两个身份、
     * 账号数据永远命中不到。
     */
    public static UUID offlineUuid(String username) {
        try {
            MessageDigest digest = MessageDigest.getInstance("MD5");
            byte[] hash = digest.digest(("OfflinePlayer:" + username).getBytes(StandardCharsets.UTF_8));
            hash[6] = (byte) ((hash[6] & 0x0F) | 0x30); // version 3
            hash[8] = (byte) ((hash[8] & 0x3F) | 0x80); // IETF variant
            long msb = 0L;
            long lsb = 0L;
            for (int i = 0; i < 8; i++) {
                msb = (msb << 8) | (hash[i] & 0xFFL);
            }
            for (int i = 8; i < 16; i++) {
                lsb = (lsb << 8) | (hash[i] & 0xFFL);
            }
            return new UUID(msb, lsb);
        } catch (Exception e) {
            throw new IllegalStateException("JDK 缺少 MD5 摘要算法", e);
        }
    }

    /** 生成 BCrypt 哈希（cost 8~16）。 */
    public static String hash(String password, int cost) {
        return BCrypt.withDefaults().hashToString(cost, password.toCharArray());
    }

    /** 是否为需要升级的旧算法哈希。 */
    public static boolean needsUpgrade(String stored) {
        return !(stored != null && (stored.startsWith("$2a$") || stored.startsWith("$2b$") || stored.startsWith("$2y$")));
    }

    /**
     * 校验密码；格式无法识别一律返回 false（fail-closed）。
     *
     * <p>BCrypt 分支先按严格策略校验；超 72 字节抛异常时再按"截断"重试一次 ——
     * 迁移自 bcryptjs / LimboAuth 的账号普遍按截断实现，否则它们能建号却永远登不上。
     */
    public static boolean verify(String password, String stored) {
        if (password == null || stored == null || stored.isEmpty()) {
            return false;
        }
        if (stored.startsWith("$2a$") || stored.startsWith("$2b$") || stored.startsWith("$2y$")) {
            try {
                return BCrypt.verifyer().verify(password.toCharArray(), stored).verified;
            } catch (IllegalArgumentException tooLong) {
                return BCrypt.verifyer(BCrypt.Version.VERSION_2A,
                        at.favre.lib.crypto.bcrypt.LongPasswordStrategies.truncate(BCrypt.Version.VERSION_2A))
                        .verify(password.toCharArray(), stored).verified;
            }
        }
        if (stored.startsWith("$SHA$")) {
            return verifyAuthMe(password, stored, "$SHA$", "SHA-256");
        }
        if (stored.startsWith("$SHA512$")) {
            return verifyAuthMe(password, stored, "$SHA512$", "SHA-512");
        }
        if (stored.length() == 32 && stored.chars().allMatch(c -> Character.digit(c, 16) >= 0)) {
            return constantTimeEquals(hex(digest(password, "MD5")), stored.toLowerCase(Locale.ROOT));
        }
        return false;
    }

    private static boolean verifyAuthMe(String password, String stored, String prefix, String algorithm) {
        String body = stored.substring(prefix.length());
        int split = body.indexOf('$');
        if (split <= 0 || split == body.length() - 1) {
            return false;
        }
        String salt = body.substring(0, split);
        String expected = body.substring(split + 1).toLowerCase(Locale.ROOT);
        String inner = hex(digest(password, algorithm));
        return constantTimeEquals(hex(digest(inner + salt, algorithm)), expected);
    }

    private static byte[] digest(String input, String algorithm) {
        try {
            return MessageDigest.getInstance(algorithm).digest(input.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException("JDK 缺少摘要算法 " + algorithm, e);
        }
    }

    private static String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16)).append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }

    private static boolean constantTimeEquals(String a, String b) {
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }

    // ------------------------------------------------------------------
    // 密码策略
    // ------------------------------------------------------------------

    /** 违规描述：消息键 + 占位符。 */
    public record Violation(String messageKey, Map<String, String> placeholders) {
    }

    /** BCrypt 的硬上限（UTF-8 字节，留 1 字节余量）。 */
    private static final int MAX_BCRYPT_BYTES = 71;

    /**
     * 校验密码是否符合策略；null 表示通过。
     *
     * <p>注册、自助改密、管理员重置共用这一处，避免"管理员能设出玩家设不了的密码"。
     */
    public static Violation check(PaperConfig config, String password) {
        if (password == null || password.isEmpty()) {
            return new Violation("error.password-empty", Map.of());
        }
        int min = config.minPasswordLength();
        int max = config.maxPasswordLength();
        if (password.length() < min || password.length() > max) {
            return new Violation("error.password-length",
                    Map.of("min", String.valueOf(min), "max", String.valueOf(max)));
        }
        if (password.getBytes(StandardCharsets.UTF_8).length > MAX_BCRYPT_BYTES) {
            return new Violation("error.password-too-long", Map.of("bytes", String.valueOf(MAX_BCRYPT_BYTES)));
        }
        for (int i = 0; i < password.length(); i++) {
            char c = password.charAt(i);
            if (Character.isWhitespace(c) || Character.isISOControl(c)) {
                return new Violation("error.password-invalid-chars", Map.of());
            }
        }
        return null;
    }
}
