plugins {
    `java-library`
}

// 平台无关的业务层：密码策略与哈希、失败计数、数据访问、配置与文本渲染、正版/基岩判定、迁移。
// 所有第三方依赖都按"运行期由平台提供"处理（compileOnly），
// 两端各自负责运行期可用了：Velocity 端 shade 重定位，Paper 端由 loader 解析。
dependencies {
    val adventureVersion = providers.gradleProperty("adventureVersion").get()
    val snakeyamlVersion = providers.gradleProperty("snakeyamlVersion").get()
    val bcryptVersion = providers.gradleProperty("bcryptVersion").get()
    val bytesVersion = providers.gradleProperty("bytesVersion").get()
    val hikariVersion = providers.gradleProperty("hikariVersion").get()
    val junitVersion = providers.gradleProperty("junitVersion").get()
    val mockitoVersion = providers.gradleProperty("mockitoVersion").get()
    val sqliteVersion = providers.gradleProperty("sqliteVersion").get()
    val mariadbVersion = providers.gradleProperty("mariadbVersion").get()
    val mysqlVersion = providers.gradleProperty("mysqlVersion").get()

    val gsonVersion = providers.gradleProperty("gsonVersion").get()

    compileOnly("com.google.code.gson:gson:$gsonVersion")
    compileOnly("net.kyori:adventure-api:$adventureVersion")
    compileOnly("net.kyori:adventure-text-minimessage:$adventureVersion")
    compileOnly("org.yaml:snakeyaml:$snakeyamlVersion")
    compileOnly("at.favre.lib:bcrypt:$bcryptVersion")
    compileOnly("at.favre.lib:bytes:$bytesVersion")
    compileOnly("com.zaxxer:HikariCP:$hikariVersion")

    // 单元测试要真跑：把上面这些"运行期依赖"补进测试类路径
    testImplementation("com.google.code.gson:gson:$gsonVersion")
    testImplementation("net.kyori:adventure-api:$adventureVersion")
    testImplementation("net.kyori:adventure-text-minimessage:$adventureVersion")
    // 单测里把组件还原成纯文本做断言
    testImplementation("net.kyori:adventure-text-serializer-plain:$adventureVersion")
    testImplementation("org.yaml:snakeyaml:$snakeyamlVersion")
    testImplementation("at.favre.lib:bcrypt:$bcryptVersion")
    testImplementation("at.favre.lib:bytes:$bytesVersion")
    testImplementation("com.zaxxer:HikariCP:$hikariVersion")
    testImplementation("org.xerial:sqlite-jdbc:$sqliteVersion")
    testImplementation("org.mariadb.jdbc:mariadb-java-client:$mariadbVersion")
    testImplementation("com.mysql:mysql-connector-j:$mysqlVersion")
    testImplementation("org.junit.jupiter:junit-jupiter:$junitVersion")
    testImplementation("org.mockito:mockito-core:$mockitoVersion")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.test {
    // 命令行上的 -D 只作用于 Gradle 自身；MariaDB 集成测试需要它们出现在**测试 JVM** 里。
    // 不传则相关用例按设计自动跳过，不影响默认构建。
    listOf(
        "mikuauth.test.mariadb.host",
        "mikuauth.test.mariadb.port",
        "mikuauth.test.mariadb.database",
        "mikuauth.test.mariadb.user",
        "mikuauth.test.mariadb.password"
    ).forEach { key ->
        providers.systemProperty(key).orNull?.let { systemProperty(key, it) }
    }
}
