// 根脚本只管三件事：版本单一来源、公共仓库、编译与测试的统一口径。
val pluginGroup: String = providers.gradleProperty("group").orNull
    ?: error("gradle.properties 缺少 group")
val pluginVersion: String = providers.gradleProperty("version").orNull
    ?: error("gradle.properties 缺少 version（禁止产出 unspecified）")

subprojects {
    group = pluginGroup
    version = pluginVersion

    repositories {
        mavenCentral()
        maven("https://repo.papermc.io/repository/maven-public/")
        maven("https://repo.codemc.io/repository/maven-releases/")
    }

    plugins.withId("java") {
        tasks.withType<JavaCompile>().configureEach {
            options.encoding = "UTF-8"
            // 三个模块统一按 Java 25 编译（Velocity 4.x 与 Paper 26.x 的运行期下限）
            options.release.set(25)
            // 只保留行号与源文件名：类文件更小，堆栈可读
            options.compilerArgs.addAll(listOf("-g:lines,source"))
        }
        tasks.withType<Test>().configureEach {
            useJUnitPlatform()
            testLogging {
                events("failed")
                exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
            }
        }
    }
}

// 两个平台的成品集中到 build/dist：CI 的 artifact / Release / Modrinth 都只认这一个目录，
// 避免把 -plain.jar（未合并公共层的空壳）也发出去。
tasks.register<Sync>("dist") {
    group = "distribution"
    description = "把代理端与纸端的成品收进 build/dist"
    dependsOn(":velocity:shadowJar", ":paper:shadowJar")
    into(layout.buildDirectory.dir("dist"))
    // Ant 通配只支持 * 与 ?，不支持 [0-9] 这类字符类；用 * 匹配再排除 plain 即可
    from(project(":velocity").layout.buildDirectory.dir("libs")) {
        include("MikuAuth-*.jar")
        exclude("*-plain.jar")
    }
    from(project(":paper").layout.buildDirectory.dir("libs")) {
        include("MikuAuth-Paper-*.jar")
        exclude("*-plain.jar")
    }
}
