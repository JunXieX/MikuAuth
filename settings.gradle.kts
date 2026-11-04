pluginManagement {
    repositories {
        gradlePluginPortal()
        maven("https://repo.papermc.io/repository/maven-public/")
    }
}

rootProject.name = "MikuAuth"

// 三个模块：公共业务层（平台无关）/ 代理端 / 纸端
include(":common", ":velocity", ":paper")
