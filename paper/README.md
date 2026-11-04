# MikuAuth-Paper

Paper 服务端的登录验证插件：玩家停在服务端的**配置阶段**（画面是"加载地形"、还没进入世界）时
弹出原版对话框完成注册/登录，通过之后连接才继续、玩家才真正进入世界。

作者：JunXieX　|　MikuMC系列插件交流群：1105054380　|　非开源项目，请勿二次分发

## 功能特性

- **进服前认证**：只有一种模式 —— 未认证的连接不会进入世界，不存在"进服后被冻结/看到地形"的窗口；
- **原生对话框**：用 Minecraft 自带的 Dialog（客户端 1.21.6+），输入框 + 按钮，不需要客户端装 MOD；
- **与代理端共用账号库**：表结构与 MikuAuth（Velocity 版）一致，可指向同一个 SQLite/MariaDB 库；
- **密码安全**：BCrypt 存储（成本可调），可读 AuthMe 的 SHA/SHA512/MD5 旧哈希并在首次登录后自动升级；
- **跨连接防暴破**：同一 IP 与同一账号分别累计失败次数，达到阈值临时封禁，重连绕不过去；
- **审计**：登录、注册、失败、封禁都写 miku_audit_log，可用 /mikuauth audit 查。

## 环境要求

| 项目 | 要求 |
| --- | --- |
| 服务端 | Paper 26.2+（Folia 亦可：调度全部走异步/区域调度器） |
| Java | 25 |
| 客户端 | 1.21.6+（低版本不会显示对话框，只能等超时被断开） |
| 可选 | MariaDB / MySQL（多服共用账号库时） |

## 安装

1. 把 MikuAuth-Paper-<版本>.jar 放进 plugins/；
2. 启动服务端 —— 首次启动会生成 plugins/MikuAuth/config.yml 与 messages.yml；
3. 按需修改配置后重启（数据库连接参数改动必须重启）。

> 首次启动时插件用 Maven 解析器下载 BCrypt 与 JDBC 驱动（需联网，仓库用阿里云 + PaperMC 镜像）。
> 离线服请把这些 jar 预置到服务端的库缓存目录 `<服务端>/libraries/<group>/<artifact>/<version>/`
> （同名 .jar 与 .pom 各一份；这个目录才是加载器的真实缓存位置），
> 或者放到 `~/.m2/repository` 的标准坐标目录。

## 配置说明

| 段落 | 作用 |
| --- | --- |
| database | sqlite / mariadb / mysql 连接参数 |
| registration | 密码长度、每 IP 账号上限 |
| login | 单次连接尝试次数、配置阶段等待上限、BCrypt 成本 |
| security | 跨连接失败计数与临时封禁 |
| dialog | 是否允许 Esc 关闭对话框（关掉后玩家只能提交或等超时） |
| audit | 审计开关与保留天数 |

login.timeout-seconds 必须小于服务端自身的配置阶段超时，否则玩家看到的是服务端的超时断开。

## 命令

| 命令 | 说明 | 权限 |
| --- | --- | --- |
| /mikuauth reload | 重载配置与语言文件 | mikuauth.admin.write |
| /mikuauth unlock <玩家或IP> | 解除登录失败的临时封禁 | mikuauth.admin.write |
| /mikuauth accounts <玩家> | 查该玩家最近登录 IP 名下的账号数 | mikuauth.admin |
| /mikuauth audit <玩家> | 查最近 15 条审计 | mikuauth.admin |

## 权限节点

| 节点 | 说明 |
| --- | --- |
| mikuauth.admin | 只读查询 |
| mikuauth.admin.write | 写操作（reload / unlock） |

## 与代理端的关系

两者**不要同时接管登录**：

- 只用代理端：本插件不装，账号库由代理端维护；
- 只用本插件：把代理端的登录功能关掉，把库指向同一份数据（表名 miku_players 一致）；
- 同一台服装两个登录插件会各弹各的框，玩家会陷入"永远输不完"的状态。

## 已知限制

- 客户端低于 1.21.6 时收不到对话框包。原生服务端上不可能出现这种客户端（版本对不上直接连不进来），
  只有在装了 ViaVersion 之类的协议转换插件时才会，此时插件会按协议号提前断开并说明原因；
- 配置阶段窗口里既没有聊天栏也没有命令，所有提示只能走对话框正文或断开画面；
- 本版本不提供 setpassword：配置阶段没有命令通道，改密请直接改库或临时关插件处理。

## 开发

- 构建：在 paper/ 目录执行 mvn -B -ntp verify（CI 已接入，产物路径 paper/target/MikuAuth-Paper-*.jar）；
- 第三方库不 shade，由 paper-plugin.yml 的 loader 在运行期解析；
- 核心时序见 cn.miku.auth.paper.PreJoinGate 的类注释。
