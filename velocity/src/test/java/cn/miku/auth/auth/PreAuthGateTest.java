package cn.miku.auth.auth;

import cn.miku.auth.config.MikuConfig;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 配置阶段闸门的"是否扣留"判定测试。
 *
 * <p>这段判定决定了"谁会被停在加载地形"：条件放宽会误扣正版玩家与已登录玩家，
 * 收紧则 pre 模式根本不生效。因此六个条件逐个锁定。
 */
class PreAuthGateTest {

    @Test
    void holdsOnlyWhenEveryConditionMatches() {
        assertTrue(PreAuthGate.shouldHold("pre", true, "limbo", "limbo", true, true));
    }

    @Test
    void postModeNeverHolds() {
        assertFalse(PreAuthGate.shouldHold("post", true, "limbo", "limbo", true, true));
    }

    @Test
    void missingRuntimeSupportNeverHolds() {
        assertFalse(PreAuthGate.shouldHold("pre", false, "limbo", "limbo", true, true),
                "运行期 packetevents 缺类时必须直接放行，让玩家走 post 流程");
    }

    @Test
    void playersWithoutPasswordAuthAreNotHeld() {
        assertFalse(PreAuthGate.shouldHold("pre", true, "limbo", "limbo", false, true),
                "正版/基岩/已认证玩家不得被扣住");
    }

    @Test
    void clientsWithoutConfigPhaseSupportAreNotHeld() {
        assertFalse(PreAuthGate.shouldHold("pre", true, "limbo", "limbo", true, false));
    }

    @Test
    void onlyAuthServerConfigurationIsHeld() {
        assertFalse(PreAuthGate.shouldHold("pre", true, "lobby", "limbo", true, true),
                "认证完成后再切目标服会重走一次配置阶段，那一次绝不能扣住");
        assertTrue(PreAuthGate.shouldHold("pre", true, "LIMBO", "limbo", true, true), "服名比较大小写不敏感");
        assertFalse(PreAuthGate.shouldHold("pre", true, null, "limbo", true, true));
    }

    @Test
    void emptyGateHasNoState() {
        PreAuthGate gate = new PreAuthGate(null, new MikuConfig(), null, null);
        UUID id = UUID.randomUUID();

        assertFalse(gate.isHeld(id));
        assertEquals(0L, gate.heldSeconds(id));
        gate.forget(id); // 幂等：不存在时也必须安全
        assertFalse(gate.consumeJustReleased(id));
    }
}
