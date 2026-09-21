package cn.miku.auth.premium;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * 轻量 HTTP GET 客户端：请求正版查询源并从 JSON 响应中提取字段。
 *
 * <p>代码来源于 VeloAuth（已获授权使用）。安全与健壮性措施：
 * 昵称经 URL 编码防止注入；响应体限制 64KB 防止恶意响应占满内存；
 * 禁用连接缓存；从不跟随重定向；显式声明 User-Agent（Mojang 与部分镜像
 * 会对缺失/默认 UA 的请求限流或直接拒绝）；GET 幂等，连接类失败重试一次。
 */
final class HttpJsonClient {

    /** 响应体大小上限。 */
    private static final int MAX_RESPONSE_BYTES = 64 * 1024;
    /** 标识自身，便于上游统计与排障（部分 API 会拒绝无 UA 的请求）。 */
    private static final String USER_AGENT =
            "MikuAuth/" + cn.miku.auth.MikuAuthPlugin.VERSION + " (+https://github.com/mikuauth)";
    /** 连接类失败的重试次数（GET 幂等，可安全重试）。 */
    private static final int RETRY_ON_CONNECT_FAILURE = 1;

    private HttpJsonClient() {
    }

    /**
     * 执行 GET 请求。
     *
     * @return 状态码与响应体（仅 200 时读取响应体）
     */
    static HttpJsonResponse get(String endpoint, String username, int timeoutMillis) throws IOException {
        String encoded = URLEncoder.encode(username, StandardCharsets.UTF_8);
        URI uri = URI.create(endpoint + encoded);

        IOException lastFailure = null;
        for (int attempt = 0; attempt <= RETRY_ON_CONNECT_FAILURE; attempt++) {
            HttpURLConnection connection = null;
            try {
                connection = (HttpURLConnection) uri.toURL().openConnection();
                connection.setRequestMethod("GET");
                connection.setInstanceFollowRedirects(false);
                connection.setConnectTimeout(timeoutMillis);
                connection.setReadTimeout(timeoutMillis);
                connection.setUseCaches(false);
                connection.setRequestProperty("User-Agent", USER_AGENT);
                connection.setRequestProperty("Accept", "application/json");

                int status = connection.getResponseCode();
                String body = null;
                if (status == HttpURLConnection.HTTP_OK) {
                    body = readBody(connection);
                }
                return new HttpJsonResponse(status, body);
            } catch (ResponseTooLargeException e) {
                // 业务性异常，重试也只会再失败一次，直接抛出
                throw e;
            } catch (IOException e) {
                // 连接/读取阶段的 IO 失败可安全重试
                lastFailure = e;
            } finally {
                if (connection != null) {
                    connection.disconnect();
                }
            }
        }
        throw lastFailure != null ? lastFailure : new IOException("请求失败");
    }

    /** 从 JSON 对象顶层提取字符串字段；任何异常都返回 null（由调用方按未知处理）。 */
    static String extractStringField(String body, String field) {
        if (body == null || body.isEmpty()) {
            return null;
        }
        try {
            JsonElement document = JsonParser.parseString(body);
            if (!document.isJsonObject()) {
                return null;
            }
            JsonObject object = document.getAsJsonObject();
            JsonElement value = object.get(field);
            if (value == null || value.isJsonNull() || !value.isJsonPrimitive()) {
                return null;
            }
            return value.getAsString();
        } catch (JsonParseException | IllegalStateException | UnsupportedOperationException e) {
            return null;
        }
    }

    private static String readBody(HttpURLConnection connection) throws IOException {
        try (InputStream input = connection.getInputStream()) {
            byte[] bytes = input.readNBytes(MAX_RESPONSE_BYTES + 1);
            if (bytes.length > MAX_RESPONSE_BYTES) {
                throw new ResponseTooLargeException();
            }
            return new String(bytes, StandardCharsets.UTF_8);
        }
    }

    /** 响应体超过上限：非重试类异常。 */
    private static final class ResponseTooLargeException extends IOException {
        private static final long serialVersionUID = 1L;

        ResponseTooLargeException() {
            super("响应体超过大小上限");
        }
    }

    record HttpJsonResponse(int statusCode, String body) {
    }
}
