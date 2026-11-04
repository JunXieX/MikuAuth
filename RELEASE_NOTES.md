MikuAuth 3.8.3 更新日志

本版新增 **Paper 服务端版本**（进服前对话框认证），并让两个构件的版本号对齐到同一条版本线。
代理端（Velocity）除版本号外无行为变化。

## 本次更新

### 1. 新增 MikuAuth-Paper（服务端版本）

文件 `MikuAuth-Paper-3.8.3.jar`，放进 Paper 的 `plugins/` 即可。它只有一个登录模式：**进服前认证**。

- 玩家停在服务端的「配置阶段」——画面是"加载地形"、尚未进入世界——时弹出原版对话框，
  认证通过后连接才继续；未认证的连接不会进入世界，不存在"进服后被冻结/看到地形"的窗口。
- 用 Paper 的 `AsyncPlayerConnectionConfigureEvent`（进服前、异步）+ 原生 Dialog API 实现，
  客户端不需要装任何东西（要求 **1.21.6+**）。
- 提交走自定义点击（`PlayerCustomClickEvent` + 对话框输入回传），密码不经过命令系统。
- 账号库与代理端**表结构一致**（`miku_players` / `miku_audit_log`），SQLite 与 MariaDB/MySQL 双后端，
  可让两端指向同一个库。
- 密码：BCrypt 存储（成本可调），能读 AuthMe 的 `$SHA$` / `$SHA512$` / MD5 旧哈希，
  首次成功登录后自动升级为 BCrypt。
- 跨连接防暴破：同一 IP 与同一账号分别累计失败次数，达阈值临时封禁，重连绕不过去。
- 管理命令：`/mikuauth reload｜unlock｜accounts｜audit`（`mikuauth.admin` / `mikuauth.admin.write`）。

影响：需要"登录前不进服"的 Paper 服不必再挂 limbo 或额外登录插件；
两端的账号库可以直接共用，从代理端迁到 Paper 不需要导数据。

> ⚠ 两个版本**不要同时接管登录**：同一台服上装两个登录插件会各弹各的框。

### 2. 两个构件版本号对齐

- `MikuAuth-3.8.3.jar`（Velocity）与 `MikuAuth-Paper-3.8.3.jar`（Paper）同版本发布；
- Paper 构件不再单走 1.0.x 版本线。

影响：服主核对 jar 时不会因为"一个 3.8.x、一个 1.0.x"而误判两者不配套。

## 升级说明

- 代理端：直接替换 `plugins/` 下的 jar 并重启即可，配置与文本无需改动。
- Paper：把 `MikuAuth-Paper-3.8.3.jar` 放进 `plugins/`，首次启动生成 `config.yml` 与 `messages.yml`；
  首次启动会用 Maven 解析器下载 BCrypt 与 JDBC 驱动（离线服请预置到 `~/.m2/repository`）。
- Paper 顶的 `login.timeout-seconds` 必须小于服务端自身的配置阶段超时，否则玩家看到的是服务端的超时断开。
- Paper 客户端低于 1.21.6 时不会显示对话框，只能超时断开；断开提示里已写明这条原因。
- 完整改动：https://github.com/JunXieX/MikuAuth/compare/v3.8.2...v3.8.3
