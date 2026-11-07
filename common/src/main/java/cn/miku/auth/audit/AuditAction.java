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
    /** 管理员操作（重置/删除密码、清除正版绑定、解锁、迁移以外的账号改动等）。 */
    ADMIN_ACTION,
    /** 账号迁移。 */
    MIGRATE,
    /** 清理陈旧的正版记录并释放昵称（死昵称清理，属破坏性操作，必须留痕）。 */
    STALE_ACCOUNT_RELEASED,
    /**
     * 无法识别的事件类型。
     *
     * <p>只在"降级运行读到新版本写入的 action"时出现：展开展示为"未知事件"，
     * 而不是伪装成"管理员操作"（那会把排障方向带偏）。
     */
    UNKNOWN;

    /**
     * 展示用中文名（管理命令的审计列表）。
     *
     * <p>放在枚举里而不是各平台命令里：两端读的是同一张表、同一份文案，
     * 新增事件类型时编译器会强制在这里补齐。
     */
    public String displayName() {
        return switch (this) {
            case LOGIN_SUCCESS -> "密码登录";
            case LOGIN_PREMIUM -> "正版免密";
            case LOGIN_BEDROCK -> "基岩免密";
            case LOGIN_SESSION -> "会话免密";
            case LOGIN_FAIL -> "密码错误";
            case REGISTER -> "注册";
            case CHANGE_PASSWORD -> "改密";
            case KICK_TIMEOUT -> "超时踢出";
            case REJECT_PREMIUM_FAILED -> "正版验证失败";
            case REJECT_NAME_SNIPE -> "昵称抢注";
            case REJECT_IP_LIMIT -> "IP 超限";
            case ADMIN_ACTION -> "管理员操作";
            case MIGRATE -> "账号迁移";
            case STALE_ACCOUNT_RELEASED -> "死昵称清理";
            case UNKNOWN -> "未知事件";
        };
    }
}
