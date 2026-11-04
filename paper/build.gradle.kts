plugins {
    java
    id("com.gradleup.shadow") version "9.6.1"
}

dependencies {
    implementation(project(":common"))

    val paperApiVersion = providers.gradleProperty("paperApiVersion").get()
    val snakeyamlVersion = providers.gradleProperty("snakeyamlVersion").get()

    compileOnly("io.papermc.paper:paper-api:$paperApiVersion")
    // 服务端自带（Bukkit 的 YamlConfiguration 就在用），只编译期需要
    compileOnly("org.yaml:snakeyaml:$snakeyamlVersion")
}

// paper-plugin.yml 里的 ${version} 由这里填充
tasks.processResources {
    val ver = project.version.toString()
    filesMatching("paper-plugin.yml") {
        expand("version" to ver)
    }
}

tasks.jar {
    archiveClassifier.set("plain")
}

tasks.shadowJar {
    archiveBaseName.set("MikuAuth-Paper")
    archiveClassifier.set("")
    mergeServiceFiles()
    // 只打 :common 的类；bcrypt / HikariCP / JDBC 驱动由 MikuAuthLoader 在启动时解析
    exclude("META-INF/*.SF", "META-INF/*.DSA", "META-INF/*.RSA", "META-INF/MANIFEST.MF")
    exclude("module-info.class", "META-INF/versions/**", "META-INF/native-image/**")
    exclude("META-INF/maven/**", "META-INF/INDEX.LIST", "META-INF/DEPENDENCIES")
}

tasks.build {
    dependsOn(tasks.shadowJar)
}
