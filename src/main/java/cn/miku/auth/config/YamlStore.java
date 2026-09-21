package cn.miku.auth.config;

import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;

/**
 * YAML 配置/语言文件的公共支撑。
 *
 * <p>原先 {@code MikuConfig} 与 {@code MikuMessages} 各自实现了一套几乎逐行相同的
 * "复制默认文件 → 解析 → 双层回退 → 点分路径查找"，本类把这段逻辑收敛到一处。
 *
 * <p>设计要点：
 * <ul>
 *   <li><b>双层回退</b>：用户文件缺键时回退插件内置默认值，升级新增配置项无需重写用户文件；</li>
 *   <li><b>快照式读取</b>：用户配置与内置默认打包在一个不可变快照里，读取时只取一次引用，
 *       避免热重载过程中读到"新用户配置 + 旧默认值"的混合状态；</li>
 *   <li><b>查找结果缓存</b>：点分路径查找（含字符串切分与逐层下钻）结果按路径缓存，
 *       热路径（BossBar 每秒渲染、命令白名单判断）不再重复解析；重载时整体清空；</li>
 *   <li><b>安全解析</b>：使用 {@link SafeConstructor}，不允许 YAML 标签构造任意 Java 对象。</li>
 * </ul>
 */
final class YamlStore {

    /** 缓存中表示"该路径确实不存在"的哨兵（{@code ConcurrentHashMap} 不允许 null 值）。 */
    private static final Object ABSENT = new Object();

    /** 当前生效的配置快照（用户层 + 默认层）。 */
    private volatile Snapshot snapshot = new Snapshot(Map.of(), Map.of());
    /** 点分路径 → 解析结果（或 ABSENT）的缓存。 */
    private final Map<String, Object> resolved = new ConcurrentHashMap<>();

    private record Snapshot(Map<String, Object> user, Map<String, Object> defaults) {
    }

    /**
     * 加载文件；文件不存在时先复制内置默认文件（保留其中的中文注释）。
     *
     * <p>文件已存在时，会先把内置模板里"用户文件还没有的配置段/键"增量补进去
     * （见 {@link ConfigUpdater}），这样升级新增的配置项在服主的文件里是可见、可改的，
     * 而不是只靠缺键回退静默生效。
     *
     * @param file            目标文件
     * @param defaultResource 内置默认资源路径（如 /config.yml）
     * @param logger          日志（可为 null）
     */
    void load(Path file, String defaultResource, Logger logger) throws IOException {
        if (file.getParent() != null) {
            Files.createDirectories(file.getParent());
        }
        if (Files.notExists(file)) {
            copyResource(defaultResource, file);
        } else {
            ConfigUpdater.merge(file, defaultResource, logger);
        }
        Map<String, Object> user = readYaml(file);
        Map<String, Object> defaults = readResource(defaultResource);
        this.snapshot = new Snapshot(user, defaults);
        // 配置内容已变化，缓存必须失效
        this.resolved.clear();
    }

    /** 内置默认文件的顶层键（用于提示用户配置缺失的段落）。 */
    Set<String> defaultTopLevelKeys() {
        return snapshot.defaults().keySet();
    }

    /** 用户文件的顶层键。 */
    Set<String> userTopLevelKeys() {
        return snapshot.user().keySet();
    }

    /** 按点分路径查找；找不到回退内置默认，仍找不到返回 null。 */
    Object lookup(String path) {
        Object cached = resolved.get(path);
        if (cached != null) {
            return cached == ABSENT ? null : cached;
        }
        Snapshot current = snapshot;
        Object value = rawFrom(current.user(), path);
        if (value == null) {
            value = rawFrom(current.defaults(), path);
        }
        resolved.put(path, value == null ? ABSENT : value);
        return value;
    }

    // ---------------------------------------------------------------------
    // 内部
    // ---------------------------------------------------------------------

    /**
     * 逐级下钻点分路径。
     * YAML 解析结果是嵌套 Map，直接 {@code map.get("a.b")} 永远返回 null，
     * 会导致所有文本显示为键名字符串。
     */
    private static Object rawFrom(Map<String, Object> map, String path) {
        if (map == null) {
            return null;
        }
        Object current = map;
        for (String part : path.split("\\.")) {
            if (!(current instanceof Map<?, ?> section)) {
                return null;
            }
            current = section.get(part);
        }
        return current;
    }

    private static Map<String, Object> readYaml(Path file) throws IOException {
        if (Files.notExists(file)) {
            return Map.of();
        }
        try (InputStream input = Files.newInputStream(file)) {
            return parse(input);
        }
    }

    private static Map<String, Object> readResource(String resource) {
        try (InputStream input = YamlStore.class.getResourceAsStream(resource)) {
            return input == null ? Map.of() : parse(input);
        } catch (IOException e) {
            return Map.of();
        }
    }

    private static void copyResource(String resource, Path target) throws IOException {
        try (InputStream input = YamlStore.class.getResourceAsStream(resource)) {
            if (input == null) {
                throw new IOException("内置默认资源缺失: " + resource);
            }
            Files.copy(input, target);
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> parse(InputStream input) {
        // SafeConstructor：不使用可构造任意对象的默认构造器
        Yaml yaml = new Yaml(new SafeConstructor(new LoaderOptions()));
        Object loaded = yaml.load(input);
        return loaded instanceof Map<?, ?> map ? (Map<String, Object>) map : Map.of();
    }
}
