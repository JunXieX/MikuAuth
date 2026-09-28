# MikuAuth

Velocity 代理端登录验证插件：Java 正版免密、基岩版免密、同 IP 会话免密、原版对话框登录，
支持 SQLite / MariaDB / MySQL，可迁移 AuthMe、LibreLogin、LimboAuth 的账号。

## 声明

本项目为 MikuMC 服务器原创插件，公开给大众免费使用，MikuMC 服务器与作者 JunXieX 享有项目著作权，本项目非开源项目，请注意。

MikuMC 系列插件交流群：1105054380

## 玩家体验

装好之后，玩家那边是这样的：

| 玩家 | 体验 |
| --- | --- |
| Java 正版玩家 | 免密直接进入正式服，不会被要求输密码 |
| 基岩版玩家（经 Floodgate 接入） | 免密直接进入正式服 |
| 离线玩家（首次） | 在认证服注册：客户端 1.21.6+ 弹出原版对话框输入密码，其他客户端用 `/register` 命令 |
| 离线玩家（再次进入） | 输过一次密码后，有效期内同一 IP 免密进入 |
| 进不去正式服的玩家 | 被后端服务器拒绝的原因会显示在聊天栏与断开画面上，不会只看到"连接中断" |

## 安全

- 正版昵称强制走正版会话校验，盗版客户端无法冒充正版玩家；
- 密码用 BCrypt 存储（成本因子可调）；密码在命令历史与日志中都无需留痕（对话框通过命令提交，请在代理日志中保持命令内容不记录）；
- 限次与风控双层：单次连接限次；跨连接按"同 IP"与"同账号"两个维度累计失败，达到阈值临时封禁，重连无法绕过；
- 登录审计日志（谁、何时、从哪、以什么方式进入）与被顶下线记录，便于事后追溯。

## 运行要求

| 项目 | 要求 |
| --- | --- |
| 代理端 | Velocity 4.x |
| Java | **Java 25**（Velocity 4.x 的最低运行版本） |
| 认证服 | `velocity.toml` 中必须登记一个独立的认证服（推荐 limbo 类服务端），未认证玩家只会被调度到该服 |
| 可选依赖 | `packetevents-velocity`（官方完整版）：只有"对话框登录"需要它；没装也能正常使用，对话框会自动降级为聊天栏提示 |
| 可选依赖 | `floodgate`：只有"基岩版免密"需要它；没装时基岩版玩家走普通密码流程 |

## 安装

1. 把 `MikuAuth-<版本>.jar` 放进 Velocity 的 `plugins/` 目录；
2. 在 `velocity.toml` 的 `[servers]` 中登记认证服（例如 `auth` 或 `limbo`），并把它写进 `try` 列表；
3. 启动代理 —— 首次启动会生成 `plugins/MikuAuth/config.yml` 与 `messages.yml`；
4. 打开 `config.yml`，把 `server.auth-server` 改成第 2 步的认证服名字，然后执行 `/mikuauth reload`（或重启代理）。

> 认证服找不到时插件会停用并在控制台报错；改完请确认控制台没有报错。

## 常见场景怎么配

| 场景 | 怎么配 |
| --- | --- |
| 只开正版（无离线玩家） | `premium.enabled: true`，`session.enabled: false` |
| 离线服（含基岩版） | `session.enabled: true`（同 IP 免密）；安装 floodgate 后 `bedrock.auto-login: true` |
| 多个代理共用一个账号库 | `database.type` 改为 `mariadb`（或 `mysql`），多个代理填同一套连接参数 |
| 不需要对话框 | `dialog.enabled: false`，玩家统一用聊天栏命令 |

## 命令与权限

| 命令 | 说明 | 谁能用 |
| --- | --- | --- |
| `/login <密码>`（别名 `l`、`log`） | 登录 | 玩家 |
| `/register <密码> <确认密码>`（别名 `reg`） | 注册 | 玩家 |
| `/changepassword <旧密码> <新密码> <确认新密码>`（别名 `cp`、`changepw`） | 自助修改密码 | 已登录的玩家 |
| `/mikuauth`（别名 `/mauth`） | 管理命令，见下表 | 权限 `mikuauth.admin` |

| 管理子命令 | 用途 |
| --- | --- |
| `/mikuauth accounts <玩家>` | 查询该玩家 IP 名下的所有账号 |
| `/mikuauth audit <玩家>` / `audit ip <IP>` | 查询登录审计日志 |
| `/mikuauth diagnose <玩家>` | 排查某昵称进不来时，回放完整判定过程 |
| `/mikuauth migrate <来源> <位置> [--dry-run]` | 迁移账号（来源：`authme` / `librelogin` / `limboauth`） |
| `/mikuauth passwd <玩家>` | 交互式重置密码（密码在聊天栏输入，不会留在命令历史） |
| `/mikuauth setpassword <玩家> <新密码>` | 直接设置密码（保留账号） |
| `/mikuauth deletepassword <玩家>` | 删除密码（账号回到未注册状态，昵称可被重新注册） |
| `/mikuauth unbind <玩家>` | 解除正版绑定 |
| `/mikuauth unlock <玩家\|IP>` | 解除登录失败的临时封禁 |
| `/mikuauth limit [数量]` | 查看 / 临时调整每 IP 账号上限 |
| `/mikuauth reload` | 重载配置与文本文件 |

未认证玩家会被限制在认证服内，且只能使用登录/注册相关命令。

## 数据库

| 类型 | 适用场景 | 说明 |
| --- | --- | --- |
| `sqlite`（默认） | 单代理 | 单文件，位于 `plugins/MikuAuth/`，无需额外安装 |
| `mariadb` / `mysql` | 多代理共享账号库 | 需要自备数据库，连接参数见 `config.yml` 的 `database` 段 |

- 表名固定为 `miku_*`，请使用独立数据库；
- **JDBC 驱动不随插件打包**：首次使用某种类型时，插件会自动从阿里云 Maven 镜像下载对应驱动
  （校验 SHA-256，失败再试 Maven Central），之后缓存在 `plugins/MikuAuth/libs/`，不再联网。
  **离线服务器**请预先下载驱动 jar 放进该目录，插件检测到后不会联网；
- 更换数据库类型不会搬运已有账号，需要自行导出/导入 `miku_players` 与 `miku_sessions` 两张表。

## 配置文件

`config.yml` 内含完整中文注释，分段如下：

| 段落 | 作用 |
| --- | --- |
| `server` | 认证服名、认证后的目标服、自动送回与日志静默 |
| `premium` | 正版验证开关、各验证源开关、超时与缓存、改名自动迁移、fail-closed |
| `bedrock` | 基岩版免密开关 |
| `session` | 同 IP 会话免密的开关、时长与续期 |
| `audit` | 审计日志开关、保留天数、查询条数、两个记录文件 |
| `migrate` | 账号迁移的位置白名单 |
| `registration` / `login` | 密码长度、每 IP 账号上限、尝试次数、认证超时、BCrypt 成本 |
| `dialog` / `display` | 对话框开关与延迟；Title / BossBar 开关与样式 |
| `database` | SQLite / MariaDB / MySQL 连接参数 |
| `security` | 跨会话失败计数与临时封禁 |
| `commands` | 命令别名 |

- 改完执行 `/mikuauth reload` 热重载；数据库连接、日志文件与命令别名需要重启代理（注释中已标注）；
- 插件升级后新增的配置项会自动补进你的文件（只增不改，写入前留 `.bak` 备份）；
- 所有游戏内可见文本（聊天 / Title / BossBar / 对话框 / 踢出原因）都在 `messages.yml`，
  支持全部 MiniMessage 标签，同时兼容传统 `&` 颜色代码与 `&#RRGGBB` 十六进制色。

## 常见问题

**玩家一直卡在认证服？**
先确认 `server.auth-server` 与 `velocity.toml` 里登记的认证服同名、且该服在线。后端服务器关闭时在线玩家会被
代理弹回认证服，默认会在后端恢复后自动送回（`server.auto-return-on-fallback`）；把这个开关关掉后，
玩家需要自己切回正式服。

**没有看到对话框？**
需要客户端 1.21.6+ 且代理安装了官方完整版 `packetevents-velocity`；任一条件不满足会自动降级为聊天栏 +
Title + BossBar 提示，功能不受影响。

**控制台看不到转服相关日志？**
默认开启静默（`server.silence-retry-failures: true`），排查转服问题时把它改成 `false`，即可看到每次失败与恢复。

**从别的登录插件迁移**
执行 `/mikuauth migrate <来源> <位置>`（支持 `authme` / `librelogin` / `limboauth`）。旧算法的哈希会被自动识别，
玩家首次登录后升级为 BCrypt，不需要让全员重置密码。建议先加 `--dry-run` 预览结果。