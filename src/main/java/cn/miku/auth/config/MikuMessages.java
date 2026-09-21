package cn.miku.auth.config;

import cn.miku.auth.util.TextUtil;
import net.kyori.adventure.text.Component;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;

/**
 * messages.yml 语言文件读取（带内置默认值回退）。
 *
 * <p>所有游戏内可见文本（聊天、Title、BossBar、对话框、踢出原因、管理命令反馈）
 * 全部集中在本文件，支持 MiniMessage 与传统 &amp; 颜色代码，可完全自定义。
 *
 * <p>文本键缺省时自动回退内置默认值，避免升级后出现"缺少文本配置"。
 * 查找与缓存细节见 {@link YamlStore}。
 */
public final class MikuMessages {

    private static final String DEFAULT_RESOURCE = "/messages.yml";

    private final YamlStore store = new YamlStore();

    /**
     * 加载语言文件。
     *
     * @param dataDirectory 插件数据目录
     * @param logger        日志
     */
    public void load(Path dataDirectory, Logger logger) throws IOException {
        store.load(dataDirectory.resolve("messages.yml"), DEFAULT_RESOURCE, logger);

        if (logger != null) {
            for (String key : store.defaultTopLevelKeys()) {
                if (!store.userTopLevelKeys().contains(key)) {
                    logger.warn("[MikuAuth] 语言文件缺少段落 '{}'，已使用内置默认文本。", key);
                }
            }
        }
    }

    /** 获取原始文本（未渲染）；键缺失时回退内置默认，再缺失返回键名本身。 */
    public String raw(String key) {
        Object value = store.lookup(key);
        return value != null ? String.valueOf(value) : key;
    }

    /** 获取原始文本列表（如多行帮助）；键缺失时回退内置默认。 */
    public List<String> rawList(String key) {
        Object value = store.lookup(key);
        if (value instanceof List<?> list) {
            return list.stream().map(String::valueOf).toList();
        }
        return List.of();
    }

    /** 渲染文本（无占位符）。 */
    public Component component(String key) {
        return component(key, Map.of());
    }

    /**
     * 渲染文本（带占位符）。
     *
     * @param key          文本键
     * @param placeholders 占位符，如 Map.of("player", name)
     */
    public Component component(String key, Map<String, String> placeholders) {
        return TextUtil.render(raw(key), placeholders);
    }

    /** 渲染并追加聊天前缀。 */
    public Component prefixed(String key, Map<String, String> placeholders) {
        return Component.text().append(component("prefix"))
                .append(component(key, placeholders))
                .build();
    }

    /** 渲染并追加聊天前缀（无占位符）。 */
    public Component prefixed(String key) {
        return prefixed(key, Map.of());
    }
}
