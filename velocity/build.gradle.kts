plugins {
    java
    id("com.gradleup.shadow") version "9.6.1"
}

dependencies {
    implementation(project(":common"))

    val velocityApiVersion = providers.gradleProperty("velocityApiVersion").get()
    val packeteventsVersion = providers.gradleProperty("packeteventsVersion").get()
    val gsonVersion = providers.gradleProperty("gsonVersion").get()
    val bcryptVersion = providers.gradleProperty("bcryptVersion").get()
    val bytesVersion = providers.gradleProperty("bytesVersion").get()
    val snakeyamlVersion = providers.gradleProperty("snakeyamlVersion").get()
    val hikariVersion = providers.gradleProperty("hikariVersion").get()
    val junitVersion = providers.gradleProperty("junitVersion").get()
    val mockitoVersion = providers.gradleProperty("mockitoVersion").get()

    compileOnly("com.velocitypowered:velocity-api:$velocityApiVersion")
    // 注解处理器负责生成 velocity-plugin.json（@Plugin 注解）
    annotationProcessor("com.velocitypowered:velocity-api:$velocityApiVersion")
    compileOnly("com.google.code.gson:gson:$gsonVersion")
    compileOnly("com.github.retrooper:packetevents-api:$packeteventsVersion")

    // 这些随插件 shade 打包并重定位（见下方 shadowJar）
    implementation("at.favre.lib:bcrypt:$bcryptVersion")
    implementation("at.favre.lib:bytes:$bytesVersion")
    implementation("org.yaml:snakeyaml:$snakeyamlVersion")
    implementation("com.zaxxer:HikariCP:$hikariVersion")

    // Gradle 的 compileOnly 不进测试类路径（Maven 的 provided 会），
    // 而代理端测试要直接 mock 平台接口，因此这里显式补一份
    testImplementation("com.velocitypowered:velocity-api:$velocityApiVersion")
    testImplementation("com.google.code.gson:gson:$gsonVersion")
    testImplementation("com.github.retrooper:packetevents-api:$packeteventsVersion")
    testImplementation("org.junit.jupiter:junit-jupiter:$junitVersion")
    testImplementation("org.mockito:mockito-core:$mockitoVersion")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.jar {
    archiveClassifier.set("plain")
}

tasks.shadowJar {
    archiveBaseName.set("MikuAuth")
    archiveClassifier.set("")
    mergeServiceFiles()
    // 与旧版 Maven 构建保持同一套重定位前缀：升级时不会出现两份类同时可见
    relocate("org.yaml.snakeyaml", "cn.miku.auth.lib.snakeyaml")
    relocate("com.zaxxer.hikari", "cn.miku.auth.lib.hikari")
    relocate("at.favre.lib.crypto.bcrypt", "cn.miku.auth.lib.bcrypt")
    relocate("at.favre.lib.bytes", "cn.miku.auth.lib.bytes")
    exclude("META-INF/*.SF", "META-INF/*.DSA", "META-INF/*.RSA", "META-INF/MANIFEST.MF")
    exclude("module-info.class", "META-INF/versions/**", "META-INF/native-image/**")
    exclude("META-INF/maven/**", "META-INF/INDEX.LIST", "META-INF/DEPENDENCIES")
}

tasks.build {
    dependsOn(tasks.shadowJar)
}

// 版本单一来源：gradle.properties 是唯一权威。@Plugin 注解需要编译期常量，
// 因此源码里保留一个 VERSION 常量 —— 这里强制校验两者一致，防止发版时漏改。
val checkVersionConstant = tasks.register("checkVersionConstant") {
    val expected = project.version.toString()
    val source = layout.projectDirectory.file("../common/src/main/java/cn/miku/auth/MikuVersion.java")
    inputs.file(source)
    inputs.property("expected", expected)
    doLast {
        val text = source.asFile.readText()
        if (!text.contains("VERSION = \"" + expected + "\"")) {
            throw GradleException(
                "MikuAuthPlugin.VERSION 与 gradle.properties 的 version ($expected) 不一致：" +
                    "改版本号时两处必须同时改"
            )
        }
    }
}

tasks.named("check") {
    dependsOn(checkVersionConstant)
}
