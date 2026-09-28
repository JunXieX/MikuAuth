package cn.miku.auth.database;

import org.slf4j.Logger;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.Driver;
import java.sql.SQLException;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;

/**
 * JDBC 驱动的按需装载器：SQLite / MariaDB / MySQL 三种驱动都不再随插件打包。
 *
 * <p><b>装载顺序</b>（每种驱动各自独立判断与缓存）：
 * <ol>
 *   <li><b>服务器已提供的驱动</b>：类路径上能加载到对应驱动类
 *       （代理/服务器自带，或本地开发与测试环境）；</li>
 *   <li><b>数据目录缓存</b>：{@code plugins/MikuAuth/libs/<驱动 jar>}
 *       （上次下载留下的，或管理员手工放入的——离线环境用这种方式预置）；</li>
 *   <li><b>自动下载</b>：依次尝试阿里云 Maven 镜像与 Maven Central，
 *       校验该驱动构件的 SHA-256 后写入缓存目录；成功一次即长期复用。</li>
 * </ol>
 *
 * <p><b>为什么不走 {@code DriverManager}</b>：下载来的驱动由独立 {@link URLClassLoader}
 * 装载，而 {@code DriverManager} 会检查"调用方类加载器能否加载该驱动类"，对独立加载器
 * 一律拒绝（表现为"No suitable driver"）；因此这里直接持有 {@link Driver} 实例，
 * 用 {@code driver.connect(...)} 建连接；连接池（HikariCP）也通过
 * {@code HikariConfig#setDriver} 直接使用该实例。
 *
 * <p>任何失败都抛出带处置说明的 {@link SQLException}：插件据此明确报错，管理员把官方
 * 驱动 jar 放入缓存目录即可（无需联网）。
 */
public final class JdbcDriverLoader {

    /**
     * 一种 JDBC 驱动的官方构件描述。
     *
     * <p>版本与 SHA-256 都是硬编码的固定值：下载与缓存校验都用它，
     * 镜像被篡改或文件损坏都会在装载前被拦下。
     */
    public record DriverSpec(String id, String version, String groupPath, String artifact,
                             String driverClass, String sha256) {

        /** 缓存文件名（固定，不含任何用户输入）。 */
        String fileName() {
            return artifact + "-" + version + ".jar";
        }

        /** 下载源：阿里云 Maven 镜像优先，其次 Maven Central。 */
        String[] mirrors() {
            String path = groupPath + "/" + artifact + "/" + version + "/" + fileName();
            return new String[]{
                    "https://maven.aliyun.com/repository/public/" + path,
                    "https://repo1.maven.org/maven2/" + path
            };
        }
    }

    /** SQLite JDBC：哈希已对照阿里云镜像与 Maven Central 两处实际文件核验一致。 */
    public static final DriverSpec SQLITE = new DriverSpec("sqlite", "3.46.1.3",
            "org/xerial", "sqlite-jdbc", "org.sqlite.JDBC",
            "4a4832720a65eaf7f4d6fd7ede52087b994dc5633c076f9e994dc0c8b4b0b4fa");

    /** MariaDB Connector/J：哈希已对照阿里云镜像与本地官方构件（.m2）核验一致。 */
    public static final DriverSpec MARIADB = new DriverSpec("mariadb", "3.4.1",
            "org/mariadb/jdbc", "mariadb-java-client", "org.mariadb.jdbc.Driver",
            "f60e4b282f1f4bdb74f0a26436ba7078a5e480b6f6702f6a7b45d9ba5e604a24");

    /** MySQL Connector/J：哈希已对照阿里云镜像与 Maven Central 两处实际文件核验一致。 */
    public static final DriverSpec MYSQL = new DriverSpec("mysql", "8.4.0",
            "com/mysql", "mysql-connector-j", "com.mysql.cj.jdbc.Driver",
            "d77962877d010777cff997015da90ee689f0f4bb76848340e1488f2b83332af5");

    /** 下载超时：连接 15 秒、读取 120 秒（构件最大约 14MB）。 */
    private static final int CONNECT_TIMEOUT_MILLIS = 15_000;
    private static final int READ_TIMEOUT_MILLIS = 120_000;
    private static final int BUFFER_SIZE = 8192;

    private final Path libsDirectory;
    private final Logger logger;
    /** 每种驱动装载一次后复用（键 = spec.id()）；其类加载器不可关闭（驱动仍在使用）。 */
    private final Map<String, Driver> loadedDrivers = new ConcurrentHashMap<>();

    public JdbcDriverLoader(Path dataDirectory, Logger logger) {
        this.libsDirectory = dataDirectory.resolve("libs");
        this.logger = logger;
    }

    /**
     * 打开一个连接（驱动按需装载）。
     *
     * @throws SQLException 驱动不可用且无法获取（附处置说明），或连接本身失败
     */
    public Connection open(DriverSpec spec, String jdbcUrl) throws SQLException {
        Connection connection = driver(spec).connect(jdbcUrl, new Properties());
        if (connection == null) {
            throw new SQLException(spec.id() + " 驱动拒绝该连接串: " + jdbcUrl);
        }
        return connection;
    }

    /** 某个驱动的缓存 jar 路径（诊断用）。 */
    public Path cachedJar(DriverSpec spec) {
        return libsDirectory.resolve(spec.fileName());
    }

    /**
     * 取（必要时装载）某个驱动的实例。
     *
     * <p>包内可见：连接池后端与测试用它拿 Driver 实例；一般调用方用 {@link #open}。
     */
    Driver driver(DriverSpec spec) throws SQLException {
        Driver cached = loadedDrivers.get(spec.id());
        if (cached != null) {
            return cached;
        }
        synchronized (this) {
            Driver existing = loadedDrivers.get(spec.id());
            if (existing != null) {
                return existing;
            }
            Driver loaded = tryClasspathDriver(spec);
            if (loaded == null) {
                Path target = cachedJar(spec);
                Path jar = isUsableJar(spec, target) ? target : download(spec, target);
                loaded = loadFromJar(spec, jar);
            }
            loadedDrivers.put(spec.id(), loaded);
            return loaded;
        }
    }

    // ---------------------------------------------------------------------
    // ① 类路径 → ② 缓存 → ③ 下载 → ④ 独立加载
    // ---------------------------------------------------------------------

    /** ① 类路径上已有的驱动（服务器自带 / 本地开发与测试环境）。 */
    private Driver tryClasspathDriver(DriverSpec spec) {
        try {
            Class<?> clazz = Class.forName(spec.driverClass());
            Driver found = (Driver) clazz.getDeclaredConstructor().newInstance();
            if (logger != null) {
                logger.info("[数据库] 使用服务器已提供的 {} 驱动（{}）", spec.id(), describeSource(clazz));
            }
            return found;
        } catch (ClassNotFoundException e) {
            return null; // 未提供：走缓存 / 下载
        } catch (ReflectiveOperationException | RuntimeException e) {
            if (logger != null) {
                logger.warn("[数据库] 类路径上的 {} 驱动不可用（{}），改用缓存/下载", spec.id(), e.toString());
            }
            return null;
        }
    }

    private static String describeSource(Class<?> clazz) {
        try {
            var source = clazz.getProtectionDomain().getCodeSource();
            return source == null ? "位置未知" : String.valueOf(source.getLocation());
        } catch (RuntimeException e) {
            return "位置未知";
        }
    }

    /** ② 缓存 jar 是否可用（存在且 SHA-256 正确）。 */
    private boolean isUsableJar(DriverSpec spec, Path jar) {
        try {
            if (!Files.isRegularFile(jar)) {
                return false;
            }
            if (spec.sha256().equals(sha256(jar))) {
                return true;
            }
            if (logger != null) {
                logger.warn("[数据库] 缓存的 {} 驱动校验和不符（{}），将重新下载", spec.id(), jar.getFileName());
            }
            return false;
        } catch (IOException e) {
            return false;
        }
    }

    /** ③ 依次尝试镜像下载；全部失败时抛出带处置说明的异常。 */
    private Path download(DriverSpec spec, Path target) throws SQLException {
        IOException lastFailure = null;
        for (String mirror : spec.mirrors()) {
            Path temp = target.resolveSibling(spec.fileName() + ".tmp");
            try {
                if (logger != null) {
                    logger.info("[数据库] 未检测到本地 {} 驱动，正在下载：{}", spec.id(), mirror);
                }
                Files.createDirectories(libsDirectory);
                downloadTo(spec, mirror, temp);
                String actual = sha256(temp);
                if (!spec.sha256().equals(actual)) {
                    throw new IOException("SHA-256 校验失败（期望 " + spec.sha256() + "，实际 " + actual + "）");
                }
                Files.move(temp, target, StandardCopyOption.REPLACE_EXISTING);
                if (logger != null) {
                    logger.info("[数据库] {} 驱动已就绪：{}（{} 字节）", spec.id(), target, Files.size(target));
                }
                return target;
            } catch (IOException e) {
                lastFailure = e;
                if (logger != null) {
                    logger.warn("[数据库] 从 {} 获取 {} 驱动失败：{}", mirror, spec.id(), e.toString());
                }
                try {
                    Files.deleteIfExists(temp);
                } catch (IOException ignored) {
                    // 残留的临时文件不影响后续流程
                }
            }
        }
        throw new SQLException("无法获取 " + spec.id() + " 驱动（自动下载全部镜像均失败）。"
                + "请检查服务器网络，或手动下载 " + spec.fileName()
                + "（SHA-256 " + spec.sha256() + "）并放入 " + libsDirectory.toAbsolutePath()
                + " 后重启代理。", lastFailure);
    }

    private static void downloadTo(DriverSpec spec, String url, Path target) throws IOException {
        HttpURLConnection connection = (HttpURLConnection) URI.create(url).toURL().openConnection();
        try {
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(CONNECT_TIMEOUT_MILLIS);
            connection.setReadTimeout(READ_TIMEOUT_MILLIS);
            connection.setUseCaches(false);
            connection.setRequestProperty("User-Agent", "MikuAuth/" + cn.miku.auth.MikuAuthPlugin.VERSION);
            int status = connection.getResponseCode();
            if (status != HttpURLConnection.HTTP_OK) {
                throw new IOException("HTTP " + status + "（" + spec.id() + "）");
            }
            try (InputStream input = connection.getInputStream()) {
                Files.copy(input, target, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            connection.disconnect();
        }
    }

    /** ④ 用独立类加载器装载下载下来的驱动。 */
    private Driver loadFromJar(DriverSpec spec, Path jar) throws SQLException {
        try {
            URLClassLoader loader = new URLClassLoader(
                    new URL[]{jar.toUri().toURL()}, JdbcDriverLoader.class.getClassLoader());
            Class<?> clazz = Class.forName(spec.driverClass(), true, loader);
            Driver loaded = (Driver) clazz.getDeclaredConstructor().newInstance();
            if (logger != null) {
                logger.info("[数据库] 已装载 {} 驱动：{}", spec.id(), jar);
            }
            return loaded;
        } catch (Throwable t) {
            // 类链接失败是 Error 而非 Exception，这里必须兜住并转成带原因的 SQLException
            throw new SQLException("装载 " + spec.id() + " 驱动失败: " + t, t);
        }
    }

    /** 流式 SHA-256（大构件不整读进内存）。 */
    private static String sha256(Path file) throws IOException {
        try (InputStream input = Files.newInputStream(file)) {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] buffer = new byte[BUFFER_SIZE];
            int read;
            while ((read = input.read(buffer)) > 0) {
                digest.update(buffer, 0, read);
            }
            StringBuilder hex = new StringBuilder(64);
            for (byte b : digest.digest()) {
                hex.append(Character.forDigit((b >> 4) & 0xF, 16));
                hex.append(Character.forDigit(b & 0xF, 16));
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IOException("JDK 缺少 SHA-256 摘要算法", e);
        }
    }
}