package cn.miku.auth.database;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.List;

/**
 * SQL 后端：屏蔽 SQLite 与 MariaDB 在<b>连接管理</b>、<b>DDL</b>、<b>upsert 语法</b>上的差异。
 *
 * <p>两端的根本差别：
 * <ul>
 *   <li>SQLite 是单文件单写者模型：全插件共用<b>一个</b>连接，由 {@link DatabaseManager}
 *       用单线程执行器串行化，彻底避免 SQLITE_BUSY；</li>
 *   <li>MariaDB 是网络数据库：使用连接池（HikariCP），允许多个操作并发执行；</li>
 *   <li>建表语句类型不同：MariaDB 主键列不能用 TEXT（需 VARCHAR(n)），时间戳用 BIGINT；</li>
 *   <li>upsert 语法不同：SQLite 用 {@code ON CONFLICT}，MariaDB 用 {@code ON DUPLICATE KEY}。</li>
 * </ul>
 *
 * <p>表名固定为 {@code miku_*}，因此 MariaDB 侧请使用<b>独立 database</b>；
 * 如需与其它系统共库，请自行加前缀隔离。
 */
interface SqlBackend extends AutoCloseable {

    /** 借出一个连接。SQLite 返回共享连接；MariaDB 从池中取出（可能阻塞至连接超时）。 */
    Connection borrow() throws SQLException;

    /** 归还连接。SQLite 为空操作；MariaDB 归还到池。 */
    void release(Connection connection);

    /** 建表与索引语句（各方言自行给出）。 */
    List<String> schemaStatements();

    /**
     * 账号表建表语句（结构定义的唯一来源）。
     * 迁移到新结构时用不同的表名复用同一份定义，避免两处结构定义漂移。
     */
    String playersDdl(String tableName);

    /**
     * 批量导入账号的 INSERT 语句：遇到主键/唯一键冲突时<b>跳过该行而不是报错</b>。
     *
     * <p>迁移场景下一次可能提交上千条，其中任何一条与既有账号冲突都不应中断整批，
     * 否则批量写入就失去意义。各后端的写法不同：
     * SQLite 用 {@code INSERT OR IGNORE}，MariaDB 用 {@code INSERT IGNORE}。
     */
    String insertIgnorePlayerSql();

    /**
     * 用迁移表替换正式账号表。
     *
     * <p>各方言的最佳做法不同：MariaDB 支持一条语句原子换名，
     * SQLite 只能先删后改（依赖 DDL 可回滚的事务）。
     */
    void swapPlayersTable(Connection connection, String migratingTable) throws SQLException;

    /** 会话表 upsert：SQLite 用 {@code ON CONFLICT}，MariaDB 用 {@code ON DUPLICATE KEY}。 */
    String upsertSessionSql();

    /**
     * 分批清理过期会话的语句（两个占位符：截止时间、单批行数）。
     *
     * <p>一次性 {@code DELETE} 掉全部历史行会独占唯一的 SQLite 工作线程，
     * 期间登录/注册任务全在排队。分批让出线程，把影响摊平。
     */
    String purgeSessionsSql();

    /** 分批清理过期审计日志的语句（两个占位符：截止时间、单批行数）。 */
    String purgeAuditSql();

    /**
     * 审计日志表建表语句。
     * 与账号表同理：结构定义放在后端，保证两种方言各自正确
     * （MariaDB 的自增列、索引语法与 SQLite 不同）。
     */
    String auditLogDdl(String tableName);

    /**
     * 数据库操作的并发线程数。
     * SQLite 必须为 1（单写者），MariaDB 可取连接池大小。
     */
    int workerThreads();

    /** 人类可读的后端描述（日志用）。 */
    String describe();

    @Override
    void close();
}
