package cn.miku.auth.database;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.helpers.NOPLogger;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.Driver;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JDBC 驱动按需装载器的测试。
 *
 * <p>测试环境里三种驱动都在类路径上（pom 中均为 provided），因此覆盖的是
 * "① 使用服务器已提供的驱动"这条路径——也正是无需缓存与下载时的正常形态；
 * ②/③（缓存校验、镜像下载）需要文件与网络，不在单测中触发。
 */
class JdbcDriverLoaderTest {

    @TempDir
    Path tempDir;

    @Test
    void usesClasspathDriverAndOpensWorkingConnection() throws SQLException {
        JdbcDriverLoader loader = new JdbcDriverLoader(tempDir, NOPLogger.NOP_LOGGER);
        String url = "jdbc:sqlite:" + tempDir.resolve("probe.db").toAbsolutePath();

        try (Connection connection = loader.open(JdbcDriverLoader.SQLITE, url);
             Statement statement = connection.createStatement()) {
            statement.executeUpdate("CREATE TABLE probe (id INTEGER PRIMARY KEY, name TEXT)");
            statement.executeUpdate("INSERT INTO probe (name) VALUES ('ok')");
            try (ResultSet rs = statement.executeQuery("SELECT name FROM probe")) {
                assertTrue(rs.next(), "插入的行应能读回");
                assertEquals("ok", rs.getString(1));
            }
        }
    }

    @Test
    void mariaDbAndMySqlDriversAreLoadedFromClasspathWithoutDownloading() throws SQLException {
        JdbcDriverLoader loader = new JdbcDriverLoader(tempDir, NOPLogger.NOP_LOGGER);

        Driver mariadb = loader.driver(JdbcDriverLoader.MARIADB);
        Driver mysql = loader.driver(JdbcDriverLoader.MYSQL);
        assertNotNull(mariadb, "MariaDB 驱动应能从类路径装载");
        assertNotNull(mysql, "MySQL 驱动应能从类路径装载");
        assertSame(mariadb, loader.driver(JdbcDriverLoader.MARIADB), "驱动装载一次后应复用");

        // 关键不变量：类路径命中时不产生下载缓存（离线环境也不会莫名发起网络请求）
        assertFalse(Files.exists(loader.cachedJar(JdbcDriverLoader.MARIADB)),
                "类路径命中时不应下载 MariaDB 驱动");
        assertFalse(Files.exists(loader.cachedJar(JdbcDriverLoader.MYSQL)),
                "类路径命中时不应下载 MySQL 驱动");
    }
}