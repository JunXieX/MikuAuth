package cn.miku.auth.auth;

import cn.miku.auth.config.MikuConfig;
import cn.miku.auth.config.MikuMessages;
import cn.miku.auth.premium.PremiumService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 正版判定器的单元测试。
 *
 * <p>重点覆盖"期望 UUID ↔ 实际 UUID"的比对协议：它是防昵称抢注的唯一关卡，
 * 一旦判定错误，攻击者就能用正版玩家的昵称登入离线模式。
 *
 * <p>这些用例全部是纯内存逻辑（不含网络查询），因此无需 mock 任何东西——
 * 这正是把判定器从状态机里拆出来的收益之一。
 */
class PremiumDeciderTest {

    @TempDir
    Path dataDirectory;

    private MikuConfig config;
    private MikuMessages messages;
    private PremiumDecider decider;

    @BeforeEach
    void setUp() throws IOException {
        Files.writeString(dataDirectory.resolve("config.yml"), """
                server:
                  auth-server: "auth"
                premium:
                  enabled: false
                """, StandardCharsets.UTF_8);
        config = new MikuConfig();
        config.load(dataDirectory, null);
        messages = new MikuMessages();
        messages.load(dataDirectory, null);
        decider = new PremiumDecider(
                new PremiumService(config, org.slf4j.helpers.NOPLogger.NOP_LOGGER),
                config, messages, org.slf4j.helpers.NOPLogger.NOP_LOGGER);
    }

    // ---------------------------------------------------------------------
    // 期望 UUID 比对（防昵称抢注）
    // ---------------------------------------------------------------------

    @Test
    void matchingUuidMarksConnectionVerified() {
        UUID mojangUuid = UUID.randomUUID();
        decider.expect("Notch", mojangUuid);

        assertNull(decider.verifyProfile("Notch", mojangUuid), "UUID 一致应放行");
        assertTrue(decider.isVerified(mojangUuid), "通过校验的连接应被标记为已验证（免密依据）");
    }

    @Test
    void mismatchedUuidIsRejectedAsNameSnipe() {
        UUID realOwner = UUID.randomUUID();
        decider.expect("Notch", realOwner);

        // 离线客户端伪装成正版昵称 → 实际 UUID 必然不同
        assertNotNull(decider.verifyProfile("Notch", UUID.randomUUID()),
                "UUID 不匹配必须拒绝（昵称抢注）");
        assertFalse(decider.isVerified(realOwner), "被拒绝的连接不得留下已验证标记");
    }

    @Test
    void connectionWithoutExpectationIsPassedThrough() {
        // 非正版决策连接（离线玩家）：没有期望记录 → 放行，交给密码/注册流程
        assertNull(decider.verifyProfile("newcomer", UUID.randomUUID()));
    }

    @Test
    void expectationLookupIsCaseInsensitive() {
        UUID mojangUuid = UUID.randomUUID();
        decider.expect("Notch", mojangUuid);

        assertNull(decider.verifyProfile("NOTCH", mojangUuid),
                "昵称比对必须归一化大小写（PreLogin 与连接后的昵称大小写可能不同）");
        assertTrue(decider.isVerified(mojangUuid));
    }

    @Test
    void expectationIsConsumedAfterVerification() {
        UUID mojangUuid = UUID.randomUUID();
        decider.expect("Notch", mojangUuid);
        decider.verifyProfile("Notch", mojangUuid);

        // 已消费：第二次（例如重连但未重新走 PreLogin）不应再命中期望
        assertNull(decider.verifyProfile("Notch", mojangUuid), "无期望记录时一律放行");
    }

    @Test
    void nullUuidIsNotRecordedAsExpectation() {
        decider.expect("Notch", null);

        assertNull(decider.verifyProfile("Notch", UUID.randomUUID()),
                "期望 UUID 未知时不应误判为抢注");
    }

    // ---------------------------------------------------------------------
    // 清理语义
    // ---------------------------------------------------------------------

    @Test
    void forgetClearsBothVerificationAndExpectation() {
        UUID mojangUuid = UUID.randomUUID();
        decider.expect("Notch", mojangUuid);
        decider.verifyProfile("Notch", mojangUuid);
        decider.expect("Notch", mojangUuid);

        decider.forget(mojangUuid, "Notch");

        assertFalse(decider.isVerified(mojangUuid), "断线后不得保留已验证标记");
        assertNull(decider.verifyProfile("Notch", mojangUuid), "断线后期望记录也应清除");
    }

    @Test
    void revokeVerifiedClearsOnlyVerification() {
        UUID mojangUuid = UUID.randomUUID();
        decider.expect("Notch", mojangUuid);
        decider.verifyProfile("Notch", mojangUuid);
        decider.expect("Notch", mojangUuid); // 再登记一次期望

        decider.revokeVerified(mojangUuid);

        assertFalse(decider.isVerified(mojangUuid), "自愈路径需要清掉已验证标记");
        assertNull(decider.verifyProfile("Notch", mojangUuid),
                "期望记录不应被 revokeVerified 影响（它仍需参与后续校验）");
    }

    @Test
    void forgetExpectationOnlyDropsPendingExpectation() {
        UUID mojangUuid = UUID.randomUUID();
        decider.expect("Notch", mojangUuid);
        decider.verifyProfile("Notch", mojangUuid);
        decider.expect("Notch", mojangUuid);

        decider.forgetExpectation("Notch");

        assertTrue(decider.isVerified(mojangUuid), "清除正版绑定不应影响已核实的连接标记");
        assertNull(decider.verifyProfile("Notch", mojangUuid), "期望记录应被清除");
    }

    @Test
    void purgeStaleKeepsFreshEntries() {
        UUID mojangUuid = UUID.randomUUID();
        decider.expect("Notch", mojangUuid);
        decider.verifyProfile("Notch", mojangUuid);

        decider.purgeStale();

        assertTrue(decider.isVerified(mojangUuid), "刚写入的条目不应被清理");
    }

    // ---------------------------------------------------------------------
    // 可用性
    // ---------------------------------------------------------------------

    @Test
    void availableReflectsConfigSwitch() {
        assertFalse(decider.available(), "配置关闭正版验证时应报告不可用");
    }
}
