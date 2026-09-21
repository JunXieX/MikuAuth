package cn.miku.auth.util;

import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import net.kyori.adventure.text.format.TextColor;
import net.kyori.adventure.text.format.TextDecoration;
import net.kyori.adventure.text.serializer.plain.PlainTextComponentSerializer;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 文本渲染测试：传统色码转换、占位符替换与转义、异常降级、静态文本缓存。
 *
 * <p>断言基于"展平后是否存在某种颜色/装饰"，不依赖 MiniMessage 具体生成的组件树形状。
 */
class TextUtilTest {

    private static List<Component> flatten(Component component) {
        List<Component> all = new ArrayList<>();
        all.add(component);
        for (Component child : component.children()) {
            all.addAll(flatten(child));
        }
        return all;
    }

    private static String plain(Component component) {
        return PlainTextComponentSerializer.plainText().serialize(component);
    }

    private static boolean hasColor(Component component, TextColor color) {
        return flatten(component).stream().anyMatch(node -> color.equals(node.color()));
    }

    private static boolean hasBold(Component component) {
        return flatten(component).stream()
                .anyMatch(node -> node.decoration(TextDecoration.BOLD) == TextDecoration.State.TRUE);
    }

    @Test
    void legacyColorCodesAreConverted() {
        Component component = TextUtil.render("&a绿色&c红色");
        assertEquals("绿色红色", plain(component));
        assertTrue(hasColor(component, NamedTextColor.GREEN));
        assertTrue(hasColor(component, NamedTextColor.RED));
    }

    @Test
    void legacyFormatCodesAreConverted() {
        Component component = TextUtil.render("&l粗体");
        assertEquals("粗体", plain(component));
        assertTrue(hasBold(component));
    }

    @Test
    void hexColorIsConverted() {
        Component component = TextUtil.render("&#ff8800橙色");
        assertEquals("橙色", plain(component));
        assertTrue(hasColor(component, TextColor.color(0xff8800)));
    }

    @Test
    void placeholdersAreSubstituted() {
        Component component = TextUtil.render("欢迎 {player} 回来", Map.of("player", "Miku"));
        assertEquals("欢迎 Miku 回来", plain(component));
    }

    @Test
    void placeholderValuesCannotInjectTags() {
        // 占位符值中的 '<' 必须被转义，否则玩家昵称可以伪造颜色、点击事件等
        Component component = TextUtil.render("{player}", Map.of("player", "<red>假名字"));
        assertEquals("<red>假名字", plain(component));
        assertFalse(hasColor(component, NamedTextColor.RED));
    }

    @Test
    void nullPlaceholderValueBecomesEmpty() {
        Map<String, String> placeholders = new HashMap<>();
        placeholders.put("player", null);
        assertEquals("你好 ", plain(TextUtil.render("你好 {player}", placeholders)));
    }

    @Test
    void brokenTagsDoNotThrow() {
        assertDoesNotThrow(() -> TextUtil.render("<color:这不是颜色>文本"));
        assertEquals("", plain(TextUtil.render(null)));
        assertEquals("", plain(TextUtil.render("")));
    }

    @Test
    void staticTextRenderIsCached() {
        // 无占位符的静态文本（前缀、Title 等）命中缓存；Adventure 组件不可变，可安全复用
        Component first = TextUtil.render("&e缓存文本");
        Component second = TextUtil.render("&e缓存文本");
        assertSame(first, second);
    }
}
