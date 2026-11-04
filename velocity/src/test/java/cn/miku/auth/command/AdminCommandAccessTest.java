package cn.miku.auth.command;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * 管理命令权限分级测试。
 *
 * <p><b>回归点</b>：子命令别名（{@code setpass} / {@code delpass} / {@code password}）曾经
 * 只出现在执行分支里，权限判定用的却是另一份"主名清单"——于是别名绕过了写权限与
 * {@code --confirm}，只持有只读节点（客服）的账号即可重置任意账号的密码。
 * 本用例锁死"别名与主名权限完全一致"，并覆盖 unlock / migrate 的权限边界。
 */
class AdminCommandAccessTest {

    @Test
    void aliasesShareTheirPrimaryNameAccessLevel() {
        assertEquals(AdminCommand.Access.WRITE_CONFIRM,
                AdminCommand.accessFor("setpass", args("setpass", "victim", "pw")),
                "setpass 必须与 setpassword 同为写 + 确认");
        assertEquals(AdminCommand.Access.WRITE_CONFIRM,
                AdminCommand.accessFor("delpass", args("delpass", "victim")),
                "delpass 必须与 deletepassword 同为写 + 确认");
        assertEquals(AdminCommand.Access.WRITE_CONFIRM,
                AdminCommand.accessFor("password", args("password", "victim")),
                "password 必须与 passwd 同为写 + 确认");

        assertEquals(AdminCommand.Access.WRITE_CONFIRM,
                AdminCommand.accessFor("setpassword", args("setpassword", "victim", "pw")));
        assertEquals(AdminCommand.Access.WRITE_CONFIRM,
                AdminCommand.accessFor("deletepassword", args("deletepassword", "victim")));
        assertEquals(AdminCommand.Access.WRITE_CONFIRM,
                AdminCommand.accessFor("passwd", args("passwd", "victim")));
    }

    /** 解除临时封禁属于写操作：只读节点不得解除暴破封禁。 */
    @Test
    void unlockRequiresWriteAndConfirm() {
        assertEquals(AdminCommand.Access.WRITE_CONFIRM,
                AdminCommand.accessFor("unlock", args("unlock", "alice")));
    }

    /** migrate 一律需要写权限（它会以服务端身份连接目标库），只有 --dry-run 免去二次确认。 */
    @Test
    void migrationAccessDependsOnDryRunOnlyForConfirmation() {
        assertEquals(AdminCommand.Access.WRITE,
                AdminCommand.accessFor("migrate",
                        args("migrate", "authme", "sqlite:auth.db", "--dry-run")));
        assertEquals(AdminCommand.Access.WRITE_CONFIRM,
                AdminCommand.accessFor("migrate", args("migrate", "authme", "sqlite:auth.db")));
    }

    @Test
    void readOnlySubcommandsStayReadOnly() {
        assertEquals(AdminCommand.Access.READ_ONLY,
                AdminCommand.accessFor("accounts", args("accounts", "alice")));
        assertEquals(AdminCommand.Access.READ_ONLY,
                AdminCommand.accessFor("audit", args("audit", "alice")));
        assertEquals(AdminCommand.Access.READ_ONLY,
                AdminCommand.accessFor("diagnose", args("diagnose", "alice")));
        assertEquals(AdminCommand.Access.READ_ONLY,
                AdminCommand.accessFor("reload", args("reload")));
        // limit 不带参数只是查看；带上数量才是写操作
        assertEquals(AdminCommand.Access.READ_ONLY,
                AdminCommand.accessFor("limit", args("limit")));
        assertEquals(AdminCommand.Access.WRITE_CONFIRM,
                AdminCommand.accessFor("limit", args("limit", "5")));
    }

    private static String[] args(String... values) {
        return values;
    }
}