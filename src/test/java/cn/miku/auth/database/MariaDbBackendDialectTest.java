package cn.miku.auth.database;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.helpers.NOPLogger;

import java.nio.file.Path;
import java.sql.SQLException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * MariaDB / MySQL 后端的方言与接线测试。
 *
 * <p>两类内容：
 * <ol>
 *   <li><b>方言差异</b>：URL 前缀与 {@code sslMode} 取值风格（两个驱动同名不同值，
 *       配错会直接连不上，因此固定断言）；</li>
 *   <li><b>驱动注入接线</b>：HikariCP 5.x 没有 setDriver，按需装载的驱动是通过
 *       {@code setDataSource} 包一层注入的——这里用"连接被拒绝"的真实尝试验证这条接线
 *       确实生效（无需真实数据库：错误信息里必须出现目标地址与排查位置）。</li>
 * </ol>
 */
class MariaDbBackendDialectTest {

    @TempDir
    Path tempDir;

    private static MariaDbBackend.Settings settings(String type, String sslMode) {
        return new MariaDbBackend.Settings(type, "db.local", 3306, "mikuauth",
                "user", "secret", sslMode, 6, 5000);
    }

    @Test
    void mysqlUsesConnectorJUrlAndUppercaseSslMode() {
        assertEquals("jdbc:mysql://db.local:3306/mikuauth?sslMode=VERIFY_IDENTITY"
                        + "&connectTimeout=5000&socketTimeout=30000",
                settings("mysql", "verify-full").jdbcUrl());
        assertEquals("jdbc:mysql://db.local:3306/mikuauth?sslMode=REQUIRED"
                        + "&connectTimeout=5000&socketTimeout=30000",
                settings("mysql", "trust").jdbcUrl());
        assertEquals("jdbc:mysql://db.local:3306/mikuauth?sslMode=DISABLED"
                        + "&connectTimeout=5000&socketTimeout=30000",
                settings("mysql", "disable").jdbcUrl());
    }

    @Test
    void mariadbKeepsItsOwnUrlAndLowercaseSslMode() {
        assertEquals("jdbc:mariadb://db.local:3306/mikuauth?sslMode=verify-ca"
                        + "&connectTimeout=5000&socketTimeout=30000",
                settings("mariadb", "verify-ca").jdbcUrl());
    }

    /**
     * 驱动注入接线：连接一个必然拒绝的端口，验证连接池确实调用了注入的驱动。
     *
     * <p>驱动的类路径可见、建连失败、异常被包装成带目标与排查位置的 SQLException ——
     * 三步都走到，才说明 {@code setDataSource} 这条注入路径真的通了
     * （HikariCP 若忽略注入的 DataSource，这里会以别的方式失败）。
     */
    @Test
    void poolUsesInjectedDriverAndReportsTargetOnConnectionFailure() {
        JdbcDriverLoader loader = new JdbcDriverLoader(tempDir, NOPLogger.NOP_LOGGER);

        for (String type : new String[]{"mariadb", "mysql"}) {
            MariaDbBackend.Settings settings = new MariaDbBackend.Settings(type, "127.0.0.1", 1, "mikuauth",
                    "user", "secret", "disable", 2, 800);
            SQLException failure = assertThrows(SQLException.class,
                    () -> new MariaDbBackend(settings, loader, NOPLogger.NOP_LOGGER),
                    type + "：连不上时必须抛出 SQLException 而不是别的异常");
            assertTrue(failure.getMessage().contains("127.0.0.1:1/mikuauth"),
                    type + "：错误信息必须包含目标地址，实际为 " + failure.getMessage());
            assertTrue(failure.getMessage().contains("database.mariadb"),
                    type + "：错误信息必须给出排查用的配置段，实际为 " + failure.getMessage());
        }
    }
}