package cn.miku.auth.audit;

/**
 * 审计事件类型。
 *
 * <p>命名对应"发生了什么"，而不是"代码在哪调用的"——查询时按此过滤即可回答
 * "这个号被人动过吗""最近暴破多不多"这类运维问题。
 */
public enum AuditAction {

    /** 密码登录成功。 */
    LOGIN_SUCCESS,
    /** 正版免密进入（代理会话校验通过）。 */
    LOGIN_PREMIUM,
    /** 基岩版免密进入（Floodgate 已验证）。 */
    LOGIN_BEDROCK,
    /** 同 IP 会话免密进入。 */
    LOGIN_SESSION,
    /** 密码错误。 */
    LOGIN_FAIL,
    /** 注册成功。 */
    REGISTER,
    /** 修改密码。 */
    CHANGE_PASSWORD,
    /** 认证超时被踢出。 */
    KICK_TIMEOUT,
    /** 因正版验证源全部失败而拒绝连接（fail-closed）。 */
    REJECT_PREMIUM_FAILED,
    /** 因正版 UUID 不匹配而拒绝（昵称抢注）。 */
    REJECT_NAME_SNIPE,
    /** 因同 IP 账号数超限而拒绝。 */
    REJECT_IP_LIMIT,
    /** 管理员操作（重置/删除密码、撤销会话、解锁等）。 */
    ADMIN_ACTION,
    /** 账号迁移。 */
    MIGRATE
}
