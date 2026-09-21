package cn.miku.auth.security;

import cn.miku.auth.config.MikuConfig;

import java.util.Map;

/**
 * 密码策略：长度与字符集的统一校验点。
 *
 * <p>玩家注册（{@code /register}）、玩家改密（{@code /changepassword}）与
 * 管理员重置（{@code /mikuauth setpassword}）必须用同一套规则，
 * 否则会出现"管理员能设出玩家自己设不了的密码"这类不一致。
 *
 * <p><b>为什么禁用空白与控制字符</b>：对话框与命令都按空格分词提交密码
 * （{@code /register $(password) $(confirm)}），含空格的密码能注册成功但永远登不上；
 * 控制字符则可能截断命令。这类密码必须在入口处就拦掉。
 */
public final class PasswordPolicy {

    /** 违规描述：消息键 + 占位符。 */
    public record Violation(String messageKey, Map<String, String> placeholders) {
    }

    private PasswordPolicy() {
    }

    /**
     * 校验密码是否符合策略。
     *
     * @return null = 通过；否则为需要展示给玩家的违规信息
     */
    public static Violation check(MikuConfig config, String password) {
        if (password == null || password.isEmpty()) {
            return new Violation("error.password-empty", Map.of());
        }
        int min = config.minPasswordLength();
        int max = config.maxPasswordLength();
        if (password.length() < min || password.length() > max) {
            return new Violation("error.password-length",
                    Map.of("min", String.valueOf(min), "max", String.valueOf(max)));
        }
        if (hasUnsupportedChars(password)) {
            return new Violation("error.password-invalid-chars", Map.of());
        }
        return null;
    }

    /** 密码是否包含命令通道无法安全承载的字符（空白与控制字符）。 */
    public static boolean hasUnsupportedChars(String password) {
        if (password == null) {
            return false;
        }
        for (int i = 0; i < password.length(); i++) {
            char c = password.charAt(i);
            if (Character.isWhitespace(c) || Character.isISOControl(c)) {
                return true;
            }
        }
        return false;
    }
}
