package cn.miku.auth.config;

import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.slf4j.Logger;

/**
 * 配置文件增量合并：把内置模板里"用户文件还没有的配置段/键"补进用户文件。
 *
 * <p><b>为什么需要</b>：插件升级新增配置项时，如果只依赖"缺键回退内置默认值"，
 * 功能虽然能用，但服主在自己的 config.yml 里<b>看不到、也就无从配置</b>
 * （典型例子：MariaDB 的连接参数）。把新段落补进文件才是可用的升级体验。
 *
 * <p><b>为什么不做整文件覆盖</b>：用户文件里有自己的设置与注释，覆盖等于丢配置。
 *
 * <p><b>安全约束</b>（每一条都对应一种"把用户文件写坏"的风险）：
 * <ul>
 *   <li><b>只增不改</b>：绝不修改、删除或重排任何已有行；</li>
 *   <li>用户文件不是合法 YAML 时<b>完全不碰</b>（看不懂的文件不动）；</li>
 *   <li>写入前先校验合并结果能解析、且新增键确实能被读到，否则<b>放弃写入</b>；</li>
 *   <li>写入前还要再查一次<b>重复键</b>——重复键会让后写入的模板默认值覆盖用户设置，
 *       是"只增不改"在语义层面被破坏的唯一途径；</li>
 *   <li>键路径的推导只依赖<b>真实缩进栈</b>，与缩进宽度无关（2 空格 / 4 空格 / 制表符都正确）；</li>
 *   <li>首次修改前留一份 {@code <文件名>.bak}；</li>
 *   <li>整个过程幂等：第二次启动不会重复插入。</li>
 * </ul>
 *
 * <p><b>废弃键的标注</b>：本类只补键、不删键，因此老配置里已经存在的废弃键只能靠
 * {@link #RETIRED_KEYS} 就地插入一行注释来标注，否则它会"看起来仍然生效"。
 * 反过来，某个键一旦重新生效（例如 {@code dialog.enabled}），就必须从该表中移除。
 */
final class ConfigUpdater {

    /** 顶层/嵌套的键行：捕获缩进、键名。 */
    private static final Pattern KEY_LINE = Pattern.compile("^(\\s*)([A-Za-z0-9_-]+):(.*)$");

    /** 追加在文件末尾的提示注释（幂等标记）。 */
    private static final String MARKER =
            "# ==== 以下段落为 MikuAuth 新增配置项（自动补充，内容与内置默认一致）====";

    /** 废弃键提示的固定前缀（同时用作幂等标记）。 */
    private static final String RETIRED_MARKER = "# \u26a0 已废弃：";

    /**
     * 已废弃的配置键：路径 → 废弃说明。
     *
     * <p>合并只增不改，因此老配置里已经存在的废弃键会永久留在服主文件中。
     * 危险之处在于：它<b>看起来仍然生效</b>——例如 2.1.0 的某个键被移除后，
     * 服主仍会以为自己的设置起作用。
     *
     * <p>处理方式：在该键<b>上一行</b>插入一条说明注释（纯插入，不改动、不删除用户写的行），
     * 让服主打开文件就能看到"这行已经没用了"。说明文本里的 {@code ⚠} 同时充当幂等标记。
     *
     * <p><b>键恢复生效时必须从这里删除</b>：{@code dialog.enabled} 曾在 2.2.0 被标记废弃
     * （当时对话框恒开），2.7.0 起它重新成为一个真实开关——留在表里会让服主看到
     * "本键不再生效"的注释，而实际上它已经生效，属于最坏的一类文档错误。
     */
    private static final Map<String, String> RETIRED_KEYS = Map.of();

    /** 合并结果。 */
    record Result(List<String> added, boolean changed) {

        static final Result NONE = new Result(List.of(), false);
    }

    private ConfigUpdater() {
    }

    /**
     * 执行增量合并。
     *
     * <p>任何异常都不会向外抛出：配置补充失败只应降级为"少几个新选项"，
     * 绝不能影响插件启动。
     */
    static Result merge(Path file, String defaultResource, Logger logger) {
        try {
            return doMerge(file, defaultResource, logger);
        } catch (Exception e) {
            if (logger != null) {
                logger.warn("[配置] 增量合并 {} 失败（文件保持原样）: {}",
                        file.getFileName(), e.toString());
            }
            return Result.NONE;
        }
    }

    // ---------------------------------------------------------------------
    // 主流程
    // ---------------------------------------------------------------------

    private static Result doMerge(Path file, String defaultResource, Logger logger) throws IOException {
        String defaultText = readResource(defaultResource);
        if (defaultText == null || defaultText.isBlank() || Files.notExists(file)) {
            return Result.NONE;
        }
        String userText = Files.readString(file, StandardCharsets.UTF_8);
        if (userText.isBlank() || tryParse(userText) == null) {
            // 空文件或语法有误的文件一律不动：前者会在别处按"缺失"重建，后者交给报错
            return Result.NONE;
        }

        // 行尾统一去掉 \r：Windows 记事本编辑过的文件是 CRLF，而 KEY_LINE 的 (.*)$
        // 无法容忍行尾的 \r，会让整个合并静默失效（曾实际踩到）
        List<String> defaultLines = splitLines(defaultText);
        List<String> userLines = new ArrayList<>(splitLines(userText));
        // 输出保持用户文件原有的换行风格
        String eol = userText.contains("\r\n") ? "\r\n" : "\n";

        Map<String, Entry> defaultEntries = collectEntries(defaultLines);
        Set<String> userPaths = collectPaths(userLines);

        // 同一插入位置可能落多个条目（例如文件末尾要追加多个顶层段落）：
        // 先按位置分组、组内保持模板顺序，再整体插入，否则反向插入会把相对顺序颠倒
        Map<Integer, List<String>> grouped = new LinkedHashMap<>();
        Map<Integer, Boolean> topLevelAt = new LinkedHashMap<>();
        List<String> added = new ArrayList<>();
        for (Entry entry : defaultEntries.values()) {
            if (userPaths.contains(entry.path())) {
                continue;
            }
            String parent = entry.parent();
            // 父段本身也缺时跳过：父段会作为整体被补进去，子项自然包含在内
            if (!parent.isEmpty() && !userPaths.contains(parent)) {
                continue;
            }
            int index;
            int indentShift;
            if (parent.isEmpty()) {
                index = userLines.size();
                indentShift = 0;
            } else {
                index = bodyEnd(userLines, parent);
                if (index < 0) {
                    continue;
                }
                // 模板块要按"用户文件自己的缩进风格"平移后再插入：
                // 模板用 2 空格、用户被编辑器重排成 4 空格时，直接把块插进去会让新键的缩进
                // 比同级键更浅 —— 那不是排版不整齐，而是**非法 YAML**（解析直接失败，
                // 合并被安全闸门放弃，用户永远看不到新配置项）
                int[] parentLocation = locateKey(userLines, parent);
                indentShift = parentLocation[0] < 0
                        ? 0
                        : childIndent(userLines, parent, parentLocation[1]) - entry.indent();
            }
            grouped.computeIfAbsent(index, ignored -> new ArrayList<>())
                    .addAll(shift(entry.block(), indentShift));
            topLevelAt.merge(index, parent.isEmpty(), (a, b) -> a || b);
            added.add(entry.path());
        }
        if (grouped.isEmpty() && !hasRetiredKeys(userLines)) {
            return Result.NONE;
        }

        // 从后往前插入，避免前面的插入导致后面的行号偏移
        List<Integer> indexes = new ArrayList<>(grouped.keySet());
        indexes.sort(Comparator.reverseOrder());
        boolean markerPending = !userText.contains(MARKER);
        for (int index : indexes) {
            List<String> block = grouped.get(index);
            if (markerPending && Boolean.TRUE.equals(topLevelAt.get(index))) {
                // 追加的顶层段落前加一次说明注释（幂等：已存在则不重复加）
                List<String> withMarker = new ArrayList<>(block.size() + 1);
                withMarker.add(MARKER);
                withMarker.addAll(block);
                block = withMarker;
                markerPending = false;
            }
            userLines.addAll(Math.min(index, userLines.size()), block);
        }

        // 废弃键提示必须放在上面这批插入之后：它们按"原始行号"倒序插入，
        // 若先插注释会让这些行号全部偏移。这里同样是纯插入，不动用户写的任何一行。
        List<String> retiredNoted = applyRetiredNotices(userLines);
        if (grouped.isEmpty() && retiredNoted.isEmpty()) {
            return Result.NONE;
        }

        String merged = String.join(eol, userLines);
        // 安全闸门：合并结果必须可解析、且新增的每个键都真的能被读到
        Map<String, Object> parsed = tryParse(merged);
        if (parsed == null || !containsAll(parsed, added)) {
            if (logger != null) {
                logger.warn("[配置] {} 的增量合并结果未通过校验，已放弃写入", file.getFileName());
            }
            return Result.NONE;
        }
        // 第二道闸门：合并结果不得含重复键。
        // 只靠上面的 containsAll 挡不住"同一个键出现两次"——SnakeYAML 默认允许重复键且
        // **后者胜**，那等于把模板默认值追加到用户写的值后面，静默改掉用户显式设置
        // （实测：用户写 "enabled": false，合并后被默认值 true 覆盖）。
        if (hasDuplicateKeys(merged)) {
            if (logger != null) {
                logger.warn("[配置] {} 的增量合并会产生重复键（会让默认值覆盖你的设置），已放弃写入。"
                        + "请检查该文件是否使用了带引号的键名（如 \"key\":）或非标准缩进",
                        file.getFileName());
            }
            return Result.NONE;
        }

        Path backup = file.resolveSibling(file.getFileName() + ".bak");
        if (Files.notExists(backup)) {
            Files.copy(file, backup);
        }
        writeAtomically(file, merged);
        if (logger != null) {
            if (!added.isEmpty()) {
                logger.info("[配置] {} 已补充新增配置项: {}（首次修改前的备份：{}）",
                        file.getFileName(), String.join(", ", added), backup.getFileName());
            }
            if (!retiredNoted.isEmpty()) {
                logger.warn("[配置] {} 含已废弃的配置项 {}，已在文件中标注——这些键不再生效，可安全删除",
                        file.getFileName(), String.join(", ", retiredNoted));
            }
        }
        return new Result(added, true);
    }

    /**
     * 原子写入：先写同目录临时文件再改名覆盖。
     *
     * <p>直接覆盖写有个真实的坏结果——写到一半进程被杀（或磁盘满）会把服主的配置
     * 截断成半个文件，而此时"原文件备份"只存在于<b>首次</b>修改之前。
     */
    private static void writeAtomically(Path file, String content) throws IOException {
        Path temp = file.resolveSibling(file.getFileName() + ".tmp");
        Files.writeString(temp, content, StandardCharsets.UTF_8);
        try {
            Files.move(temp, file, java.nio.file.StandardCopyOption.REPLACE_EXISTING,
                    java.nio.file.StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException atomicUnsupported) {
            // 个别文件系统不支持原子改名：退回普通覆盖，但仍避免"写到一半"
            Files.move(temp, file, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        }
    }

    // ---------------------------------------------------------------------
    // 废弃键提示
    // ---------------------------------------------------------------------

    /** 用户文件中是否存在已废弃的键（用于决定"无新增项时是否还要写文件"）。 */
    private static boolean hasRetiredKeys(List<String> lines) {
        for (String path : RETIRED_KEYS.keySet()) {
            if (locateKey(lines, path)[0] >= 0) {
                return true;
            }
        }
        return false;
    }

    /**
     * 为每个废弃键插入一行说明注释（幂等）。
     *
     * @return 本次实际插入提示的键路径；已提示过的不计入
     */
    private static List<String> applyRetiredNotices(List<String> lines) {
        List<String> noted = new ArrayList<>();
        for (Map.Entry<String, String> retired : RETIRED_KEYS.entrySet()) {
            int[] located = locateKey(lines, retired.getKey());
            int index = located[0];
            if (index < 0) {
                continue;                                   // 用户文件里没有这个键
            }
            if (index > 0 && lines.get(index - 1).contains(RETIRED_MARKER)) {
                continue;                                   // 已提示过，保持幂等
            }
            // 注释按该键的缩进对齐，保证插入后段落排版不错乱
            lines.add(index, " ".repeat(located[1]) + RETIRED_MARKER + retired.getValue());
            noted.add(retired.getKey());
        }
        return noted;
    }

    /**
     * 定位某键路径所在的行号与缩进。
     *
     * @return {行号, 缩进}；行号为 -1 表示该路径不存在
     */
    private static int[] locateKey(List<String> lines, String path) {
        for (KeyHit hit : keyHits(lines)) {
            if (path.equals(hit.path())) {
                return new int[]{hit.lineIndex(), hit.indent()};
            }
        }
        return new int[]{-1, 0};
    }

    /** 一行键：行号、缩进（绝对空格数）、由缩进栈推导出的完整路径。 */
    private record KeyHit(int lineIndex, int indent, String path) {
    }

    /**
     * 扫描键行并推导完整键路径。
     *
     * <p><b>为什么不用「缩进 ÷ 2」</b>：那等于假定每级恰好缩进 2 个空格。服主用编辑器
     * 重排成 4 空格缩进、或把文件交给格式化工具后，同一级的键会被串成子级，键路径整体错位
     * （实测：4 空格文件里 `server.auth-server` 的兄弟键被算成 `server.auth-server.fallback-server`），
     * 于是合并结果通不过安全校验 —— 该用户的新配置项<b>永远补不进去</b>。
     *
     * <p>这里的规则与 YAML 一致：只比较<b>绝对缩进值</b>，弹出所有"缩进 ≥ 当前行"的层级，
     * 与缩进宽度（2 空格 / 4 空格 / 制表符）无关。
     */
    private static List<KeyHit> keyHits(List<String> lines) {
        List<KeyHit> hits = new ArrayList<>();
        Deque<Integer> indents = new ArrayDeque<>();
        Deque<String> keys = new ArrayDeque<>();
        for (int i = 0; i < lines.size(); i++) {
            Matcher matcher = KEY_LINE.matcher(lines.get(i));
            if (!matcher.matches()) {
                continue;
            }
            int indent = matcher.group(1).length();
            while (!indents.isEmpty() && indent <= indents.peekLast()) {
                indents.pollLast();
                keys.pollLast();
            }
            String key = matcher.group(2);
            hits.add(new KeyHit(i, indent,
                    keys.isEmpty() ? key : String.join(".", keys) + "." + key));
            indents.addLast(indent);
            keys.addLast(key);
        }
        return hits;
    }

    // ---------------------------------------------------------------------
    // 解析
    // ---------------------------------------------------------------------

    /** 默认模板中的一个条目：路径、键行缩进、完整块（含前导注释与空行）。 */
    private record Entry(String path, int indent, List<String> block) {

        String parent() {
            int dot = path.lastIndexOf('.');
            return dot < 0 ? "" : path.substring(0, dot);
        }
    }

    /**
     * 把默认模板拆成"路径 → 块"。
     *
     * <p>块的起点会向前吸收连续的注释/空行（它们属于该段落，例如 {@code # ----} 分隔头），
     * 终点则回退掉属于下一段的尾随注释。
     */
    private static Map<String, Entry> collectEntries(List<String> lines) {
        Map<String, Entry> entries = new LinkedHashMap<>();
        List<KeyHit> keyLines = keyHits(lines);
        for (int k = 0; k < keyLines.size(); k++) {
            KeyHit hit = keyLines.get(k);
            int index = hit.lineIndex();
            int indent = hit.indent();
            int end = lines.size();
            for (int j = k + 1; j < keyLines.size(); j++) {
                if (keyLines.get(j).indent() <= indent) {
                    end = keyLines.get(j).lineIndex();
                    break;
                }
            }
            // 回退掉属于下一段的尾随注释与空行
            while (end > index + 1 && isBlankOrComment(lines.get(end - 1))) {
                end--;
            }
            // 向前吸收属于本段的注释与空行
            int start = index;
            while (start > 0 && isBlankOrComment(lines.get(start - 1))) {
                start--;
            }
            entries.put(hit.path(), new Entry(hit.path(), indent,
                    new ArrayList<>(lines.subList(start, end))));
        }
        return entries;
    }

    /**
     * 用户文件里某段落的"子项缩进"：该段落第一层子键的缩进。
     *
     * <p>用来把模板块平移到与用户文件一致的缩进风格（见 {@code doMerge} 里的说明）。
     * 该段落还没有任何子项时，退化为"父键缩进 + 2"（内置模板的风格）。
     */
    private static int childIndent(List<String> lines, String parentPath, int parentIndent) {
        boolean foundParent = false;
        for (KeyHit hit : keyHits(lines)) {
            if (!foundParent) {
                foundParent = parentPath.equals(hit.path());
                continue;
            }
            return hit.indent() > parentIndent ? hit.indent() : parentIndent + 2;
        }
        return parentIndent + 2;
    }

    /** 按 delta 个空格整体平移一个块（正数缩进、负数回退），空行与注释的相对位置保持不变。 */
    private static List<String> shift(List<String> block, int delta) {
        if (delta == 0) {
            return block;
        }
        List<String> shifted = new ArrayList<>(block.size());
        for (String line : block) {
            if (line.isBlank()) {
                shifted.add(line);
                continue;
            }
            if (delta > 0) {
                shifted.add(" ".repeat(delta) + line);
            } else {
                int leading = line.length() - line.stripLeading().length();
                int strip = Math.min(-delta, leading);
                shifted.add(strip > 0 ? line.substring(strip) : line);
            }
        }
        return shifted;
    }

    /** 收集用户文件里所有层级的键路径。 */
    private static Set<String> collectPaths(List<String> lines) {
        Set<String> paths = new LinkedHashSet<>();
        for (KeyHit hit : keyHits(lines)) {
            paths.add(hit.path());
        }
        return paths;
    }

    /**
     * 找到某段落"最后一行内容"之后的位置（即新子项应插入的行号）。
     *
     * <p>段落范围 = 键行开始，直到遇到"缩进不比自己深的键行"或"顶格注释"（下一段的分隔头）。
     *
     * @return -1 = 找不到该段落
     */
    private static int bodyEnd(List<String> lines, String parentPath) {
        int keyIndex = -1;
        int keyIndent = 0;
        for (KeyHit hit : keyHits(lines)) {
            if (parentPath.equals(hit.path())) {
                keyIndex = hit.lineIndex();
                keyIndent = hit.indent();
                break;
            }
        }
        if (keyIndex < 0) {
            return -1;
        }
        int lastContent = keyIndex;
        for (int i = keyIndex + 1; i < lines.size(); i++) {
            String line = lines.get(i);
            if (line.startsWith("#")) {
                break;                                  // 顶格注释 = 下一段的分隔头
            }
            Matcher matcher = KEY_LINE.matcher(line);
            if (matcher.matches() && matcher.group(1).length() <= keyIndent) {
                break;                                  // 同级或更浅的键 = 本段结束
            }
            if (matcher.matches() || line.strip().length() > 0) {
                lastContent = i;
            }
        }
        return lastContent + 1;
    }

    /** 按行切分，并去掉行尾的 {@code \r}（兼容 CRLF 文件）。 */
    private static List<String> splitLines(String text) {
        String[] raw = text.split("\n", -1);
        List<String> lines = new ArrayList<>(raw.length);
        for (String line : raw) {
            lines.add(line.endsWith("\r") ? line.substring(0, line.length() - 1) : line);
        }
        return lines;
    }

    private static boolean isBlankOrComment(String line) {
        String trimmed = line.strip();
        return trimmed.isEmpty() || trimmed.startsWith("#");
    }

    private static boolean containsAll(Map<String, Object> parsed, List<String> paths) {
        for (String path : paths) {
            Object current = parsed;
            for (String part : path.split("\\.")) {
                if (!(current instanceof Map<?, ?> map)) {
                    return false;
                }
                current = map.get(part);
            }
            if (current == null) {
                return false;
            }
        }
        return true;
    }

    private static Map<String, Object> tryParse(String text) {
        try {
            Object loaded = new Yaml(new SafeConstructor(new LoaderOptions())).load(text);
            @SuppressWarnings("unchecked")
            Map<String, Object> map = loaded instanceof Map<?, ?> parsed ? (Map<String, Object>) parsed : null;
            return map;
        } catch (RuntimeException e) {
            return null;
        }
    }

    /**
     * 合并结果是否含重复键。
     *
     * <p>SnakeYAML 默认允许重复键（<b>后者胜</b>），而重复键几乎只可能来自"把整段模板重复追加"
     * ——那会让模板默认值盖掉用户自己的设置。因此用「禁止重复键」重新解析一次作为第二道闸门：
     * 解析失败即放弃写入（宁可少补几个新选项，也不能静默改用户的配置）。
     */
    private static boolean hasDuplicateKeys(String text) {
        LoaderOptions options = new LoaderOptions();
        options.setAllowDuplicateKeys(false);
        try {
            new Yaml(new SafeConstructor(options)).load(text);
            return false;
        } catch (RuntimeException e) {
            return true;
        }
    }

    private static String readResource(String resource) {
        try (InputStream input = ConfigUpdater.class.getResourceAsStream(resource)) {
            return input == null ? null : new String(input.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            return null;
        }
    }
}
