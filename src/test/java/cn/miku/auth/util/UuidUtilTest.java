package cn.miku.auth.util;

import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * 账号 UUID 工具测试。
 *
 * <p>重点：离线 UUID 必须与 Velocity 分配给玩家的完全一致（直接委托其
 * {@code UuidUtils.generateOfflinePlayerUuid}），否则同一玩家会被算成两个身份。
 */
class UuidUtilTest {

    @Test
    void offlineUuidIsDeterministic() {
        assertEquals(UuidUtil.offlineUuid("Notch"), UuidUtil.offlineUuid("Notch"));
    }

    @Test
    void offlineUuidDiffersByNameAndIsCaseSensitive() {
        // 离线模式下"账号即昵称"：不同昵称必须是不同身份
        assertNotEquals(UuidUtil.offlineUuid("alice"), UuidUtil.offlineUuid("bob"));
        // 大小写不同 → 不同 UUID（与代理按原始昵称分配的行为一致）
        assertNotEquals(UuidUtil.offlineUuid("Alice"), UuidUtil.offlineUuid("alice"));
    }

    @Test
    void offlineUuidMatchesVanillaAlgorithm() {
        // 原版/Velocity 的离线 UUID = MD5 版 UUID v3("OfflinePlayer:" + name)
        UUID expected = UUID.nameUUIDFromBytes("OfflinePlayer:Notch".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        assertEquals(expected, UuidUtil.offlineUuid("Notch"));
    }

    @Test
    void offlineUuidIsVersion3() {
        assertEquals(3, UuidUtil.offlineUuid("Notch").version());
    }

    @Test
    void parseHandlesNullAndGarbage() {
        assertNull(UuidUtil.parse(null));
        assertNull(UuidUtil.parse(""));
        assertNull(UuidUtil.parse("   "));
        assertNull(UuidUtil.parse("not-a-uuid"));
    }

    @Test
    void parseAcceptsStandardFormWithWhitespace() {
        UUID uuid = UUID.randomUUID();
        assertEquals(uuid, UuidUtil.parse(uuid.toString()));
        assertEquals(uuid, UuidUtil.parse("  " + uuid + "  "));
    }

    @Test
    void formatIsLowercaseStandardForm() {
        UUID uuid = UUID.fromString("123E4567-E89B-12D3-A456-426614174000");
        assertEquals("123e4567-e89b-12d3-a456-426614174000", UuidUtil.format(uuid));
        assertNull(UuidUtil.format(null));
    }
}
