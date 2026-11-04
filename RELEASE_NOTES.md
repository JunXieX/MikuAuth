MikuAuth 3.8.2 更新日志

本版新增「进服前登录」模式，并让对话框提交不再经过命令系统。**默认行为与 3.8.0 完全一致**。

## 本次更新

### 1. 新增两种登录模式（`login.mode`）

- **post（默认）**：与 3.8.0 一致 —— 需要密码的玩家先进认证服，Join Game 之后弹对话框。
- **pre（新增）**：对话框改为在认证服的「配置阶段」弹出。此时玩家还在"加载地形"、尚未进入世界，
  认证成功后代理才放行进入世界；体验上等同 AuthMe 的 pre-join 登录。

实现用的是 Velocity 自带的等待型事件（`PlayerConfigurationEvent`）：代理会等事件返回的
task 完成后才写 `finish_configuration` 并切换状态，因此**不向客户端补发任何协议包**，
也就没有"包状态错位导致客户端断线"的风险。

不支持配置阶段对话框的客户端（低于 1.21.11，或协议版本无法识别）自动按 post 处理 ——
功能不缺失，只是晚一步看到对话框。

> 两种模式下未认证连接都只落在认证服（limbo），目标服不会因为假连接压测多承担流量。
> 开启 pre 时请确认 `login.pre.timeout-seconds`（默认 30 秒）小于认证服自身的配置阶段超时，
> 否则玩家看到的是认证服的超时断开，而不是本插件的提示。

### 2. 对话框提交流程不再经过命令系统

此前对话框按钮执行 `/login <密码>`，密码会进入代理的 `.console_history`、玩家客户端历史
与命令日志，因此文档里一直有一条"请不要开启命令内容记录"的免责提示。
现在默认改为客户端直回传（`custom_click_action`）：密码不经过命令系统，那条提示已随之删除。

- 新增配置 `dialog.submit-channel`：`custom`（默认）/ `command`（兼容兜底）；
- `pre` 模式恒为 custom —— 配置阶段没有命令通道，用 command 会导致密码无法提交。

### 3. `/mikuauth diagnose` 增加「登录模式」一行

排查"玩家卡在加载地形"时，输出的第一行就是当前模式，以及该玩家是否正被扣在配置阶段、
已经等待了多少秒。

## 升级说明

- 直接替换 `plugins/` 下的 jar 并重启代理即可；`config.yml` 会自动补进 `login.mode`、
  `login.pre.*`、`dialog.submit-channel`（只增不改，写入前留 `.bak` 备份）。
- `messages.yml` 会补进 `dialog.*.cancel-button*`、`kick.login-cancelled`、
  `admin.diagnose.mode-*`。
- 依赖：`packetevents-velocity` 需为含配置阶段对话框的版本（2.11.0 起已具备）。
  未安装或版本过旧时 pre 模式自动退化为 post，不会导致玩家进不去。
- 完整改动：https://github.com/JunXieX/MikuAuth/compare/v3.8.0...v3.8.2
