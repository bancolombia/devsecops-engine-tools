package co.com.bancolombia.devsecopsenginetools.utils.http;

import co.com.bancolombia.devsecopsenginetools.ui.tool.LogPanelLogger;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

@RequiredArgsConstructor
public class HttpClient {
    private final OkHttpClient client;

    public HttpClient() {
        this(new OkHttpClient());
    }

    @SneakyThrows
    public <T> T get(String url, Class<T> tClass) {
        return get(url, tClass, null);
    }

    @SneakyThrows
    public <T> T get(String url, Class<T> tClass, AuthMethod authMethod) {
        LogPanelLogger.info("If you have certificate issues the JAVA_HOME used is: "
                + System.getProperty("java.home"));
        Request.Builder builder = new Request.Builder()
                .url(url)
                .get();
        if (authMethod != null) {
            authMethod.inject(builder);
        }
        try (Response response = client.newCall(builder.build()).execute()) {
            if (response.isSuccessful()) {
                return new ObjectMapper()
                        .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
                        .readValue(response.body().bytes(), tClass);
            }else {
                LogPanelLogger.error("Error getting response from " + url + ": " + response.code() +
                        " " + response.message());
                LogPanelLogger.error(response.body().string());
                return null;
            }
        }
    }
}
