MikuAuth 3.9.0 更新日志

本版不动认证流程，改的是**代码怎么组织**：代理端（Velocity）与纸端（Paper）此前各写一套业务逻辑，
现在收敛成一个公共模块，两端只保留平台适配层；构建从 Maven 换成 Gradle。
代理端与纸端共用同一个版本号、同一份配置文件、同一份语言文件。

## 为什么改

同一套规则被抄了两遍，代价已经付过：

- 代理端对话框的输入框上限早已跟随 `registration.max-password-length`，
  纸端复制品漏了这一句 → 3.8.6 才补上"长密码输不进"；
- 两套 `messages.yml` 各自维护，已经出现"写了没人调"的键漂移；
- 密码策略在代理端有单测（`PasswordPolicyTest`），在纸端被内联进工具类，没有测试覆盖。

## 结构

```
MikuAuth/
├── common/    平台无关业务层：密码策略与哈希、失败计数、数据访问与建表、
│              配置与文本渲染、正版/基岩判定、账号迁移、离线 UUID
├── velocity/  代理端：事件、命令、DialogService（PacketEvents 发包）、PreAuthGate
└── paper/     纸端：配置阶段闸门、原生 Dialog、Brigadier 命令、日志适配
```

纸端删掉了自己那份 `Crypto` / `Store` / `Throttle` / `Messages` / `PaperConfig`，
改用公共层的 `PasswordHasher` / `PasswordPolicy` / `DatabaseManager` / `LoginThrottle` /
MikuConfig` / `MikuMessages`。因此纸端**顺带**获得此前只有代理端才有的能力：

- **MariaDB / MySQL 账号库**（`database.type`，与代理端共用同一张表）；
- **按需下载 JDBC 驱动**（`JdbcDriverLoader`：类路径 → 数据目录 `libs/` 缓存 → 镜像下载 + SHA-256 校验），
  不再需要把三个驱动都塞进加载器；
- **更完整的审计与失败计数**（`AuditLogger` / `LoginThrottle`，含跨连接封禁与 IP/账号双维度）。

公共层不再依赖任何日志门面：新增 `LogSink` 接口，代理端用 slf4j 适配、纸端用
`java.util.logging` 适配。纸端也因此不再需要自带一个文本渲染器。

## 配置与数据

- `config.yml`、`messages.yml` **只有一份**（由 `common` 提供）。纸端读到的是同一份文件，
  与代理端相关的段落（认证服、正版验证、会话免密等）在纸端不生效，可原样保留。
- 新增 `dialog.allow-close-with-escape`（默认 `false`，仅纸端生效）：
  按 Esc 关掉对话框后玩家既看不到聊天栏也无法重开，只能等超时被断开。
- 纸端数据库文件名改由 `database.file` 决定（默认 `database.db`，与代理端一致）。
  **首次启动会把旧的 `auth.db` 自动改名为 `database.db`**（连同 `-wal`/`-shm`），账号数据不受影响。

## 构建

- Maven → Gradle：提交 `gradlew` 与 wrapper，命令 `./gradlew build`（成品在 `build/dist`）。
- 版本唯一来源是 `gradle.properties` 的 `version`；源码里的 `MikuAuthPlugin.VERSION`
  （`@Plugin` 注解需要编译期常量）由 `checkVersionConstant` 任务校验，改漏了构建直接失败。
- CI 一次构建同时产出 `MikuAuth-<版本>.jar`（代理端）与 `MikuAuth-Paper-<版本>.jar`（纸端），
  两个构件版本号一致。

## 升级说明

- 代理端：替换 jar 即可，配置键未改名。
- 纸端：替换 jar 后重启；`auth.db` → `database.db` 自动迁移；旧 `messages.yml` 可保留
  （缺失键回退内置默认值），也可删除让它重新生成。
- 完整改动：https://github.com/JunXieX/MikuAuth/compare/v3.8.6...v3.9.0
