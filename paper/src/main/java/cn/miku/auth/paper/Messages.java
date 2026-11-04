package cn.miku.auth.paper;

import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.minimessage.MiniMessage;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.configuration.file.YamlConfiguration;

import java.io.File;
import java.util.Map;

/**
 * messages.yml 的渲染入口（MiniMessage 为主，兼容 {@code &} 颜色代码）。
 *
 * <p>缺键时回退内置默认值：升级新增文案后老文件无需改写。
 * 占位符值先转义尖括号，避免玩家昵称里带 {@code <} 时被当成标签解析。
 */
public final class Messages {

    private static final MiniMessage MINI = MiniMessage.miniMessage();

    private final MikuAuthPlugin plugin;
    private final FileConfiguration defaults;
    private FileConfiguration user;

    Messages(MikuAuthPlugin plugin) {
        this.plugin = plugin;
        // 内置默认：从 jar 读取，作为缺键回退
        java.io.InputStream stream = plugin.getResource("messages.yml");
        this.defaults = stream == null
                ? new YamlConfiguration()
                : YamlConfiguration.loadConfiguration(new java.io.InputStreamReader(stream, java.nio.charset.StandardCharsets.UTF_8));
        reload();
    }

    void reload() {
        File file = new File(plugin.getDataFolder(), "messages.yml");
        if (!file.exists()) {
            plugin.saveResource("messages.yml", false);
        }
        this.user = YamlConfiguration.loadConfiguration(file);
    }

    /** 原始文本；缺键回退内置默认，再缺返回键名本身。 */
    public String raw(String key) {
        String value = user.getString(key);
        if (value == null) {
            value = defaults.getString(key);
        }
        return value == null ? key : value;
    }

    public Component component(String key, Map<String, String> placeholders) {
        String text = raw(key);
        if (placeholders != null) {
            for (Map.Entry<String, String> entry : placeholders.entrySet()) {
                text = text.replace("{" + entry.getKey() + "}", escape(entry.getValue()));
            }
        }
        try {
            return MINI.deserialize(legacyToMiniMessage(text));
        } catch (RuntimeException e) {
            return Component.text(text);
        }
    }

    public Component component(String key) {
        return component(key, Map.of());
    }

    /** 带前缀的聊天提示。 */
    public Component prefixed(String key, Map<String, String> placeholders) {
        return Component.text().append(component("prefix")).append(component(key, placeholders)).build();
    }

    private static String escape(String value) {
        return value == null ? "" : value.replace("\\", "\\\\").replace("<", "\\<");
    }

    /** {@code &a} → {@code <green>} 与 {@code &#RRGGBB} → {@code <#RRGGBB>}。 */
    private static String legacyToMiniMessage(String input) {
        if (input.indexOf('&') < 0) {
            return input;
        }
        String text = input.replaceAll("&#([0-9a-fA-F]{6})", "<#$1>");
        StringBuilder out = new StringBuilder(text.length());
        String codes = "0123456789abcdefklmnor";
        String[] tags = {"black", "dark_blue", "dark_green", "dark_aqua", "dark_red", "dark_purple",
                "gold", "gray", "dark_gray", "blue", "green", "aqua", "red", "light_purple",
                "yellow", "white", "obfuscated", "bold", "strikethrough", "underlined", "italic", "reset"};
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == '&' && i + 1 < text.length()) {
                int idx = codes.indexOf(Character.toLowerCase(text.charAt(i + 1)));
                if (idx >= 0) {
                    out.append('<').append(tags[idx]).append('>');
                    i++;
                    continue;
                }
            }
            out.append(c);
        }
        return out.toString();
    }
}
