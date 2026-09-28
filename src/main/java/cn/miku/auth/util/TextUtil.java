package cn.miku.auth.util;

import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.minimessage.MiniMessage;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/**
 * 文本渲染工具：MiniMessage 为主，兼容传统 &amp; 颜色代码与 &amp;#RRGGBB 十六进制色。
 *
 * <p>设计要点：
 * <ul>
 *   <li>占位符使用 {key} 形式，替换前转义值中的 MiniMessage 标签字符，防止注入；</li>
 *   <li>配置中写错标签不会导致插件崩溃，降级为纯文本输出；</li>
 *   <li>解析本身是纯函数；<b>唯一的共享状态</b>是下文的静态渲染缓存
 *       （有 1024 上限，键为"渲染前的原文"，因此 reload 改过文本后不会命中旧组件），
 *       缓存以 {@link java.util.concurrent.ConcurrentHashMap} 承载，可跨线程调用；</li>
 *   <li>无占位符的静态文本（前缀、Title、帮助行等）渲染结果做有界缓存，
 *       Adventure 组件不可变，可安全复用。</li>
 * </ul>
 */
public final class TextUtil {

    private static final MiniMessage MINI = MiniMessage.miniMessage();

    /** 传统颜色代码：&amp;0-9a-fk-or */
    private static final Pattern LEGACY = Pattern.compile("&[0-9a-fk-orA-FK-OR]");
    /** 十六进制色：&amp;#RRGGBB */
    private static final Pattern HEX = Pattern.compile("&#([0-9a-fA-F]{6})");
    /** 静态文本渲染缓存上限（超出即整体清空，缓存只是性能优化）。 */
    private static final int MAX_CACHE_SIZE = 1024;
    private static final Map<String, Component> STATIC_CACHE = new ConcurrentHashMap<>();

    private TextUtil() {
    }

    /**
     * 渲染文本为 Adventure 组件。
     *
     * @param raw          原始文本（支持 MiniMessage 与传统 &amp; 代码）
     * @param placeholders 占位符（可为 null）；占位符值中的标签字符会被转义
     * @return 渲染后的组件；解析异常时返回纯文本组件，保证不崩溃
     */
    public static Component render(String raw, Map<String, String> placeholders) {
        if (raw == null || raw.isEmpty()) {
            return Component.empty();
        }
        boolean hasPlaceholders = placeholders != null && !placeholders.isEmpty();
        if (!hasPlaceholders) {
            Component cached = STATIC_CACHE.get(raw);
            if (cached != null) {
                return cached;
            }
        }
        String text = raw;
        if (LEGACY.matcher(text).find() || HEX.matcher(text).find()) {
            text = legacyToMiniMessage(text);
        }
        if (hasPlaceholders) {
            for (Map.Entry<String, String> entry : placeholders.entrySet()) {
                text = text.replace("{" + entry.getKey() + "}", escape(entry.getValue()));
            }
        }
        Component result;
        try {
            result = MINI.deserialize(text);
        } catch (RuntimeException ex) {
            // 配置写错时降级为纯文本，不让异常扩散
            result = Component.text(stripTags(raw, placeholders));
        }
        if (!hasPlaceholders) {
            if (STATIC_CACHE.size() >= MAX_CACHE_SIZE) {
                STATIC_CACHE.clear();
            }
            STATIC_CACHE.put(raw, result);
        }
        return result;
    }

    /** 渲染无占位符文本。 */
    public static Component render(String raw) {
        return render(raw, null);
    }

    /** 转义 MiniMessage 特殊字符，防止占位符值破坏标签结构。 */
    private static String escape(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("\\", "\\\\").replace("<", "\\<");
    }

    /** 降级路径：去掉所有 MiniMessage 标签后做占位符替换，返回可读纯文本。 */
    private static String stripTags(String raw, Map<String, String> placeholders) {
        String text = raw.replaceAll("<[^>]*>", "");
        if (placeholders != null) {
            for (Map.Entry<String, String> entry : placeholders.entrySet()) {
                text = text.replace("{" + entry.getKey() + "}", entry.getValue() == null ? "" : entry.getValue());
            }
        }
        return text;
    }

    /** 将传统颜色代码转换为 MiniMessage 标签。 */
    private static String legacyToMiniMessage(String input) {
        // 先处理十六进制色：&#RRGGBB -> <#RRGGBB>
        String text = HEX.matcher(input).replaceAll("<#$1>");
        StringBuilder builder = new StringBuilder(text.length());
        Map<Character, String> tags = Map.ofEntries(
                Map.entry('0', "<black>"), Map.entry('1', "<dark_blue>"),
                Map.entry('2', "<dark_green>"), Map.entry('3', "<dark_aqua>"),
                Map.entry('4', "<dark_red>"), Map.entry('5', "<dark_purple>"),
                Map.entry('6', "<gold>"), Map.entry('7', "<gray>"),
                Map.entry('8', "<dark_gray>"), Map.entry('9', "<blue>"),
                Map.entry('a', "<green>"), Map.entry('b', "<aqua>"),
                Map.entry('c', "<red>"), Map.entry('d', "<light_purple>"),
                Map.entry('e', "<yellow>"), Map.entry('f', "<white>"),
                Map.entry('k', "<obfuscated>"), Map.entry('l', "<bold>"),
                Map.entry('m', "<strikethrough>"), Map.entry('n', "<underlined>"),
                Map.entry('o', "<italic>"), Map.entry('r', "<reset>"));
        for (int i = 0; i < text.length(); i++) {
            char current = text.charAt(i);
            if (current == '&' && i + 1 < text.length()) {
                String tag = tags.get(Character.toLowerCase(text.charAt(i + 1)));
                if (tag != null) {
                    builder.append(tag);
                    i++;
                    continue;
                }
            }
            builder.append(current);
        }
        return builder.toString();
    }
}
