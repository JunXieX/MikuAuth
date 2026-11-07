MikuAuth 3.10.1 更新日志

本版是 3.10.0 收口后继续深读的产物：把数据层（1245 行）、认证状态机尾部（约 1000 行）、
配置增量合并（556 行）与纸端进服闸门（508 行）逐行读完，确认 1 处缺陷 + 1 处重复实现。

## 修复

### 纸端：把 login.max-tries 配成 0 时，第一次输错密码就被断开

`login.max-tries` 的口径是"0 = 不限"，代理端一直按这个口径处理（`max > 0 && tries >= max`），
但纸端进服闸门直接写了 `tries >= max-tries`，0 于是等价于"一次都不许错"。
影响：把该项配成 0 想让玩家不限次数时，纸端玩家第一次输错就被以"尝试次数过多"断开，
而配置里看不出任何异常——属于"改了配置却把玩家挡在门外"的那一类。

## 清理

### 账号注册的 INSERT 写了两遍

`register` 与 `registerWithIpLimit` 各自手写同一段 9 列 INSERT 与参数绑定，后者已经走
`insertPlayer`。改为 `register` 也复用它，删掉 22 行重复代码；异常语义不变
（唯一冲突 → DUPLICATE，其余 → ERROR）。

## 查过但不改

- **纸端认证成功后的提示可能残留**：配置阶段没有聊天栏，提示存进 `pendingChat` 等玩家进世界补发；
  玩家若在那一刻掉线、永不进世界，该条目留到重启。每条只是一个 Component，触发条件极窄。
- **`cleanup(UUID)` 的 `sessions.remove` 是无条件删除**：开启"顶号"时旧连接的断线清理理论上
  能删掉新连接的会话。新连接下一条命令会经 `ensureSession` 自愈，`authenticatedConnections`
  也已按实例比对保护，不为"顶号 + 数秒内重连"这一组合再加状态判断。
- **纸端 `/mikuauth accounts|audit` 在命令线程 `join()` 数据库**：管理员命令，SQLite 单线程下
  最坏几十毫秒，改成异步回调要把命令体拆散。

## 升级说明

- 两端只需替换 jar，配置与数据无需改动。
- 完整改动：https://github.com/JunXieX/MikuAuth/compare/v3.10.0...v3.10.1
