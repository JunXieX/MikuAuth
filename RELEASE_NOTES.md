MikuAuth 3.8.4 更新日志

本版只修 Paper 版的一个启动失败问题：**插件在部分服务端上根本加载不起来**。
代理端（Velocity）除版本号外无行为变化。

## 本次修复

### Paper 版启动报 `Error resolving libraries`、插件无法启用

现象：

```
[ERROR]: [DirectoryProviderSource] Error loading plugin: Error resolving libraries
io.papermc.paper.plugin.loader.library.LibraryLoadingException: Error resolving libraries
Caused by: ... The following artifacts could not be resolved:
  at.favre.lib:bcrypt:jar:0.10.2 (absent), org.xerial:sqlite-jdbc:jar:3.46.1.3 (absent), ...
```

原因：3.8.3 在修另一条报错（Paper 不允许插件自行声明 Maven Central）时，把仓库声明整个删掉了；
而 `MavenLibraryResolver` **没有任何默认仓库**，于是所有构件都解析不到，
插件在加载阶段就失败 —— 不是运行时出错，是整个插件没起来。

现在改为声明两个**镜像**（都不是 Maven Central 本身）：

1. 阿里云 `https://maven.aliyun.com/repository/public/`（国内优先）；
2. PaperMC `https://repo.papermc.io/repository/maven-public/`（代理 Central，兜底）。

影响：插件恢复正常加载；国内服务器首次启动下载依赖也不会卡在 Central 上。

> 离线服仍然可以预置：把这些 jar 放进 `~/.m2/repository` 的标准坐标目录，解析会直接命中缓存。
> 首次启动必须能访问上面两个镜像之一。

## 升级说明

- 代理端：直接替换 jar 即可，配置与文本无需改动。
- Paper：替换 `MikuAuth-Paper-3.8.4.jar` 后重启；如果 3.8.3 已经下载过依赖，本版会直接命中缓存。
- 完整改动：https://github.com/JunXieX/MikuAuth/compare/v3.8.3...v3.8.4
