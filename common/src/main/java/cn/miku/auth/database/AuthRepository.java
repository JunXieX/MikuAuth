package cn.miku.auth.database;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

/**
 * 账号与会话仓储接口：认证状态机只依赖这个契约，而不是具体的数据库实现。
 *
 * <p><b>为什么需要它</b>：
 * <ul>
 *   <li><b>可测试</b>：{@link AuthManager} 的决策链（正版/基岩/会话免密判定、注册与登录分流）
 *       过去完全无法单测——因为 {@link DatabaseManager} 是 final 类，且测试环境不便起真实数据库。
 *       有了接口，测试可以用内存实现（Fake）驱动全部分支；</li>
 *   <li><b>解耦</b>：认证流程后续若接入其他存储后端（Redis 缓存层、只读副本等），
 *       只需再提供一个实现，无需改动状态机。</li>
 * </ul>
 *
 * <p>所有方法都是异步的（返回 {@link CompletableFuture}），调用方（事件线程）不得阻塞等待。
 * 实现方约定：失败时以异常完成 future，绝不抛出到调用线程。
 *
 * <p>具体实现见 {@link DatabaseManager}（SQLite / MariaDB 双后端）。
 */
public interface AuthRepository {

    /** 按昵称查找账号（大小写不敏感）。 */
    CompletableFuture<Optional<StoredPlayer>> findPlayer(String nickname);

    /** 按 UUID 查找账号（账号身份键，用于识别正版改名）。 */
    CompletableFuture<Optional<StoredPlayer>> findPlayerByUuid(UUID uuid);

    /** 注册新账号。 */
    CompletableFuture<DatabaseManager.RegisterResult> register(
            UUID uuid, String nickname, String passwordHash, String authType, String ip);

    /**
     * 注册新账号，并在<b>同一次任务</b>内检查"同 IP 离线账号数"配额。
     *
     * <p>与 {@link #register} 分开是为了让"判定 + 写入"在同一时刻完成：
     * 分成"先 countAccountsByIp 再 register"两步时，同 IP 并发注册可以双双通过检查。
     *
     * @param maxAccounts ≤0 表示不限制
     */
    CompletableFuture<DatabaseManager.RegisterResult> registerWithIpLimit(
            UUID uuid, String nickname, String passwordHash, String authType, String ip, int maxAccounts);

    /** 把某 UUID 的账号迁移到新昵称（正版改名）。 */
    CompletableFuture<Boolean> renameAccount(UUID uuid, String newNickname);

    /** 释放被"陈旧正版记录"占用的昵称（死昵称清理）。 */
    CompletableFuture<Boolean> releaseStaleAccount(String nickname, UUID expectedUuid);

    /** 更新密码哈希。 */
    CompletableFuture<Boolean> updatePassword(String nickname, String passwordHash);

    /** 删除密码（账号回到未设置密码状态）。 */
    CompletableFuture<Boolean> deletePassword(String nickname);

    /** 清除正版绑定，把账号降级为离线账号。 */
    CompletableFuture<Boolean> clearPremiumBinding(String nickname);

    /**
     * 认证成功时的一次性收尾：刷新同 IP 会话 + 记录最近登录。
     *
     * @param expiresAtMillis ≤0 表示本次不写会话（会话免密关闭时）
     */
    CompletableFuture<Void> finishLogin(String nickname, String ip, long expiresAtMillis);

    /** 统计某 IP 名下的离线账号数量（配额检查）。 */
    CompletableFuture<Integer> countAccountsByIp(String ip);

    /** 列出某 IP 名下的所有账号。 */
    CompletableFuture<List<StoredPlayer>> findAccountsByIp(String ip);

    /** 写入/刷新同 IP 免密会话。 */
    CompletableFuture<Void> saveSession(String nickname, String ip, long expiresAtMillis);

    /** 查询有效会话（已过期的不返回）。 */
    CompletableFuture<Optional<DatabaseManager.Session>> findSession(String nickname);

    /** 删除会话（改密/重置密码后让旧会话立即失效）。 */
    CompletableFuture<Void> clearSession(String nickname);

    /** 清理全部过期会话。 */
    CompletableFuture<Integer> purgeExpiredSessions();
}
