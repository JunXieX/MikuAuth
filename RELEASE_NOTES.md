MikuAuth 3.8.5 更新日志

本版修 Paper 版的一个**进服前对话框必崩**问题：玩家连入时对话框发不出去，直接被断开。
代理端（Velocity）除版本号外无行为变化。

## 本次修复

### Paper：对话框提交动作的 payload 类型错误

现象（真机日志）：

```
[WARN]: [MikuAuth] [认证] 玩家 的配置阶段认证异常:
        java.lang.IllegalArgumentException: Additions must be a compound tag
[INFO]: 玩家 lost connection: 认证服务暂时不可用，请稍后重试。
```

原因：对话框按钮的 `DialogAction.customClick(Key, BinaryTagHolder)` 要求 payload 是 NBT **compound**，
而 3.8.4 传的 `BinaryTagHolder.binaryTagHolder(String)` 是 **string** tag，被 Paper 在编码阶段直接拒绝，
于是每一条连接都走异常分支被断开 —— 等于 Paper 版装上去谁进不来。

修复：改用 `CompoundBinaryTag.empty()`（登录/注册由服务端会话判定，payload 无需携带任何数据）。

影响：对话框可以正常下发，认证流程恢复。

## 升级说明

- Paper：替换 `MikuAuth-Paper-3.8.5.jar` 后重启即可，配置与数据无需改动。
- 代理端：直接替换 jar，行为与 3.8.4 一致。
- 完整改动：https://github.com/JunXieX/MikuAuth/compare/v3.8.4...v3.8.5
