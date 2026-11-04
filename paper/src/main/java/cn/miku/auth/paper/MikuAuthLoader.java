package cn.miku.auth.paper;

import io.papermc.paper.plugin.loader.PluginClasspathBuilder;
import io.papermc.paper.plugin.loader.PluginLoader;
import io.papermc.paper.plugin.loader.library.impl.MavenLibraryResolver;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.eclipse.aether.graph.Dependency;
import org.eclipse.aether.repository.RemoteRepository;

/**
 * 运行期依赖装载器：插件 jar 不 shade 任何第三方库。
 *
 * <p>由 {@code paper-plugin.yml} 的 {@code loader:} 指定；服务端启动时先把这里声明的构件
 * 下到 {@code <服务端>/libraries} 再加进插件类加载器，成品 jar 只有几十 KB。
 *
 * <p><b>这里只声明公共层真正引用的三类库</b>：BCrypt（密码哈希）、HikariCP（MariaDB 连接池，
 * 走 SQLite 时不会加载）、SnakeYAML（配置/语言文件解析）。JDBC 驱动不在这里 ——
 * 公共层的 {@code JdbcDriverLoader} 会按 {@code database.type} 只下载真正需要的那一个，
 * 并校验 SHA-256，避免"装个 SQLite 服却下了三个驱动"。
 *
 * <p>离线服：这些构件首次启动会联网下载；无法联网时请预先把 jar 放进
 * {@code <服务端>/libraries/<group>/<artifact>/<version>/}（同名 .jar 与 .pom 各一份，
 * 这个目录才是加载器的真实缓存位置），或放进 {@code ~/.m2/repository} 的标准坐标目录。
 */
public final class MikuAuthLoader implements PluginLoader {

    @Override
    public void classloader(PluginClasspathBuilder classpathBuilder) {
        MavenLibraryResolver resolver = new MavenLibraryResolver();
        // 仓库有两个约束，必须同时满足（两条都是实测踩出来的）：
        //   ① Paper 不允许插件自行声明 Maven Central（id=central / repo1.maven.org），
        //      声明了会抛 "Plugin used Maven Central for library resolution"；
        //   ② 完全不声明仓库时，MavenLibraryResolver 没有任何默认源，
        //      解析直接失败：所有构件报 (absent)，插件连加载都过不去（Leaf 26.2 上复现）。
        // 因此这里用两个镜像：阿里云优先（国内快），回落到 PaperMC 的 public 仓库（它代理 Central）。
        resolver.addRepository(new RemoteRepository.Builder(
                "aliyun", "default", "https://maven.aliyun.com/repository/public/").build());
        resolver.addRepository(new RemoteRepository.Builder(
                "papermc", "default", "https://repo.papermc.io/repository/maven-public/").build());
        // 与 gradle.properties 保持一致（构建脚本里由 Gradle 校验过，这里写死运行期坐标）
        resolver.addDependency(new Dependency(new DefaultArtifact("at.favre.lib:bcrypt:0.10.2"), "runtime"));
        resolver.addDependency(new Dependency(new DefaultArtifact("at.favre.lib:bytes:1.5.0"), "runtime"));
        resolver.addDependency(new Dependency(new DefaultArtifact("com.zaxxer:HikariCP:5.1.0"), "runtime"));
        resolver.addDependency(new Dependency(new DefaultArtifact("org.yaml:snakeyaml:2.2"), "runtime"));
        classpathBuilder.addLibrary(resolver);
    }
}
