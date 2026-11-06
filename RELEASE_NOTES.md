MikuAuth 3.9.2 更新日志

本版继续上一轮的全量自检：把尚未逐行读过的部分（事件入口、管理命令、转服调度、对话框服务、
审计落盘、JDBC 驱动装载、三种 SQL 后端、正版查询的 HTTP 层）全部读完，改动只落在确认有问题的地方。
共 3 处改动（2 修复 + 1 清理），其余检查项记录在下方"查过但不改"里。

## 修复

### 调大正版查询并发上限后重载，正常玩家会被判成"无法完成正版验证"

`premium.max-in-flight-queries` 允许配到 1024，但查询线程池的队列容量在构造期就按当时的值定型
（`max(256, 上限×3)`），而 `/mikuauth reload` 只改运行期上限、不会重建线程池。
于是"启动时 32、之后改成 512 再 reload"这种最常见的调参顺序会让队列仍是 256，
而准入控制已放行 512 个在途查询，超出的叶子任务被 `AbortPolicy` 拒绝、结果落成 UNKNOWN ——
在默认 fail-closed 下就是玩家被拒之门外。这与该文件自己写下的"队列随准入上限一起放大"直接矛盾。

现在队列按"配置允许的最大值"一次性开足（1024×3，约 24KB 引用数组），
上限无论怎么 reload 都装得下；上限的数字改为 `MikuConfig.MAX_PREMIUM_IN_FLIGHT_QUERIES` 单一来源，
并补了一条回归用例钉住这个不变量。

### `database.type: mysql` 时 `ssl-mode` 写错会静默降级成明文连接

配置校验只盯 `database.mariadb.ssl-mode` 这一个键，而 `database.type: mysql` 时实际读的是
`database.mysql.ssl-mode`（该段缺键才回落到 mariadb 段）。结果是在 mysql 段里把 `verify-ca`
写成 `verify_ca`，TLS 被静默关掉、日志里一个字都没有——跨公网明文传输账号口令。
现在校验用的是"实际生效的键路径"，两种类型都会被拦下并告警。

## 清理

### `UuidUtil.sameUuid` 是没人调用的"常量时间比较"

UUID 不是密钥，比较它没有时序侧信道可防；而这个方法是按位拆成 16 字节数组再走
`MessageDigest.isEqual`，每次调用两次数组分配。全项目零调用点（唯一的用途写在注释里的
"迁移/查重"，实际调用的是 `equals`），属于典型的防御性残留，已连同 `uuidBytes` 一起删除。

## 查过但不改（附理由，避免后人重复评估）

- **`PremiumService` 快路径可能先于权威源给出结论**：镜像先回 PREMIUM 而 Mojang 尚未回 OFFLINE 时会
  提前采信镜像。这是类注释里写明的取舍（没有冲突证据时不等待慢源），为此改成"等齐再判"会用
  Mojang 的抖动拖垮所有免密登录。
- **`AuditLogger` 的失败合并是滑动窗口**：持续暴破期间同一账号+IP 只留第一条、不再按分钟补记。
  次数统计与临时封禁由 `LoginThrottle` 独立完成，审计只用于事后回溯"被拒过"，够用。
- **`AccountMigrator` 关闭时最多等 5 秒**：迁移若正卡在批量写入的 `join()` 上，5 秒后仍会放弃等待
  并继续关库。加长等待或改成可中断写入，代价都比"关服时可能有一条 NoClassDefFoundError 日志"大。
- **`AdminCommand` 的破坏性操作仍接受命令行明文密码**：`setpassword` 的密码会进 `.console_history`。
  交互式的 `passwd`（聊天栏输入、不进历史）已经存在并在帮助里推荐，保留 `setpassword` 是为了
  让服主能一条命令批量处理；删掉它反而会让自动化运维退回手打。
- **`JdbcDriverLoader` 在 `synchronized` 块内下载驱动**：首次装载会阻塞到下载完成（最长 2×135 秒）。
  这只发生在启动期或首次切换数据库类型时，此时本来就没有玩家在线。
- **`SqliteBackend.swapPlayersTable` 先 DROP 再 RENAME**：SQLite 没有原子换名，依赖 DDL 事务回滚；
  这是该方言下唯一可行写法。

## 升级说明

- 两端都只需替换 jar，配置与数据无需改动。
- 完整改动：https://github.com/JunXieX/MikuAuth/compare/v3.9.1...v3.9.2
