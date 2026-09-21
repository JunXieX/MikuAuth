package cn.miku.auth.bedrock;

import java.lang.reflect.Method;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import org.slf4j.Logger;

/**
 * 基岩版玩家检测：通过反射调用 Floodgate API，不产生硬依赖。
 *
 * <p>代码思路来源于 VeloAuth（已获授权使用）。要点：
 * <ul>
 *   <li>Floodgate 在加密握手阶段（早于 Velocity 的 PreLoginEvent）就注册了玩家，
 *       因此 PreLogin 时即可用昵称/UUID 判断是否为基岩版；</li>
 *   <li>API 实例由 Floodgate 在自身初始化时发布，<b>不能缓存早期 null</b>，
 *       否则基岩版支持会永久失效；方法句柄只解析一次；</li>
 *   <li>所有反射异常都静默降级为“非基岩版”，让玩家走常规验证流程。</li>
 * </ul>
 */
public final class BedrockDetector {

    private static final String API_CLASS = "org.geysermc.floodgate.api.FloodgateApi";
    private static final AtomicReference<ApiMethods> METHODS = new AtomicReference<>();
    private static volatile boolean apiMissing;

    private BedrockDetector() {
    }

    /**
     * 获取 Floodgate 的实际用户名前缀；Floodgate 不可用时返回兜底值。
     * 供认证流程在记录决策键时同时覆盖"带前缀/无前缀"两种昵称形态。
     */
    public static String getLivePrefix(String fallbackPrefix, Logger logger) {
        ApiMethods methods = resolveMethods();
        if (methods == null) {
            return fallbackPrefix;
        }
        try {
            Object instance = methods.getInstance().invoke(null);
            if (instance == null) {
                return fallbackPrefix;
            }
            Object prefix = methods.getPlayerPrefix().invoke(instance);
            return prefix instanceof String value ? value : fallbackPrefix;
        } catch (ReflectiveOperationException | RuntimeException | LinkageError e) {
            if (logger != null) {
                logger.debug("[基岩版] 读取 Floodgate 前缀失败: {}", e.getMessage());
            }
            return fallbackPrefix;
        }
    }

    /**
     * 判断已建立连接的 UUID 是否属于基岩版玩家。
     * Floodgate 的 Java 侧 UUID 固定为 {@code new UUID(0, xuid)}，此特征可作为快速短路。
     */
    public static boolean isBedrockPlayer(UUID playerId) {
        if (playerId == null || playerId.getMostSignificantBits() != 0L) {
            return false;
        }
        ApiMethods methods = resolveMethods();
        if (methods == null) {
            return false;
        }
        try {
            Object instance = methods.getInstance().invoke(null);
            return instance != null
                    && Boolean.TRUE.equals(methods.isFloodgatePlayer().invoke(instance, playerId));
        } catch (ReflectiveOperationException | RuntimeException | LinkageError ignored) {
            return false;
        }
    }

    /**
     * 判断 PreLogin 阶段的用户名是否为基岩版玩家：
     * 前缀匹配（配置兜底）优先，其次在 Floodgate 在线注册表中精确查找。
     */
    public static boolean isBedrockUsername(String username, String fallbackPrefix, Logger logger) {
        if (username == null || username.isEmpty()) {
            return false;
        }
        ApiMethods methods = resolveMethods();
        if (methods == null) {
            return false;
        }
        try {
            Object instance = methods.getInstance().invoke(null);
            if (instance == null) {
                return false;
            }
            // 1) 前缀判断：Java 版用户名不允许出现 '.' 等前缀字符
            String prefix = methods.getPlayerPrefix().invoke(instance) instanceof String live
                    ? live : fallbackPrefix;
            if (prefix != null && !prefix.isEmpty() && username.startsWith(prefix)) {
                return true;
            }
            // 2) 注册表精确匹配（前缀可能被配置为空）
            Object players = methods.getPlayers().invoke(instance);
            if (players instanceof Iterable<?> iterable) {
                for (Object player : iterable) {
                    if (player != null && matchesName(player, username)) {
                        return true;
                    }
                }
            }
            return false;
        } catch (ReflectiveOperationException | RuntimeException | LinkageError e) {
            if (logger != null) {
                logger.debug("[基岩版] Floodgate API 调用失败: " + e.getMessage());
            }
            return false;
        }
    }

    private static boolean matchesName(Object player, String username) {
        for (String methodName : new String[]{"getCorrectUsername", "getJavaUsername", "getUsername"}) {
            try {
                Object candidate = player.getClass().getMethod(methodName).invoke(player);
                if (candidate instanceof String value && value.equalsIgnoreCase(username)) {
                    return true;
                }
            } catch (ReflectiveOperationException | RuntimeException | LinkageError ignored) {
                // 尝试下一个方法名
            }
        }
        return false;
    }

    // ---------------------------------------------------------------------
    // 反射句柄解析（仅一次）
    // ---------------------------------------------------------------------

    private static ApiMethods resolveMethods() {
        ApiMethods cached = METHODS.get();
        if (cached != null || apiMissing) {
            return cached;
        }
        try {
            Class<?> apiClass = Class.forName(API_CLASS);
            ApiMethods methods = new ApiMethods(
                    apiClass.getMethod("getInstance"),
                    apiClass.getMethod("isFloodgatePlayer", UUID.class),
                    apiClass.getMethod("getPlayers"),
                    apiClass.getMethod("getPlayerPrefix"));
            METHODS.compareAndSet(null, methods);
            return METHODS.get();
        } catch (ClassNotFoundException e) {
            apiMissing = true;
            return null;
        } catch (ReflectiveOperationException | RuntimeException | LinkageError ignored) {
            return null;
        }
    }

    private record ApiMethods(Method getInstance, Method isFloodgatePlayer,
                              Method getPlayers, Method getPlayerPrefix) {
    }
}
