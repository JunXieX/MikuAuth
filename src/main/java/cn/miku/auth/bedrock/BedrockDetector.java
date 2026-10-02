package cn.miku.auth.bedrock;

import java.lang.reflect.Method;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import org.slf4j.Logger;

/**
 * 基岩版玩家检测：通过反射调用 Floodgate API，不产生硬依赖。
 *
 * <p>实现要点：
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
     * 判断已建立连接的 UUID 是否属于基岩版玩家。
     *
     * <p>只以 Floodgate 的 API 结论为准，<b>不做"UUID 高位为 0"的前置短路</b>：
     * 那条特征是 Floodgate 的内部实现细节，一旦它改用别的 UUID 方案，短路就会让所有
     * 基岩玩家被误判成 Java 玩家、被迫走注册/登录；而 {@code isFloodgatePlayer} 只是一次
     * 已缓存的反射调用，省不下多少开销，却把判定绑死在一条不受我们控制的假设上。
     */
    public static boolean isBedrockPlayer(UUID playerId) {
        if (playerId == null) {
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
     * 判断 PreLogin 阶段的用户名是否为基岩版玩家。
     *
     * <p><b>只信 Floodgate 的在线注册表，不依据用户名前缀</b>：前缀只是客户端自报字符串，
     * 把"名字以某个字符开头"当成身份凭证，等于让连接方自己声明身份——任何能自造昵称的
     * 客户端都能冒充基岩玩家。Floodgate 在加密握手阶段就已按 XUID 完成身份绑定，
     * 它的注册表才是唯一权威依据；因此这里逐条比对注册表中的玩家昵称，前缀一概不看。
     *
     * <p>代价：Floodgate 不可用时基岩玩家无法被识别（会走离线注册/登录），
     * 这是刻意的取舍——宁可多输一次密码，也不接受可伪造的身份判定。
     */
    public static boolean isBedrockUsername(String username, Logger logger) {
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
            // 注册表精确匹配：逐个比对 Floodgate 已注册玩家的昵称
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
                    apiClass.getMethod("getPlayers"));
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
                              Method getPlayers) {
    }
}
