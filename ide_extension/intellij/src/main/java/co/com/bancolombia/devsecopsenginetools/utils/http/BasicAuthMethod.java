package co.com.bancolombia.devsecopsenginetools.utils.http;

import okhttp3.Request;

import static java.util.Base64.getEncoder;

public class BasicAuthMethod implements AuthMethod {
    private final String basic;

    public BasicAuthMethod(String user, String password) {
        this.basic = getEncoder().encodeToString((user + ":" + password).getBytes());
    }

    @Override
    public void inject(Request.Builder builder) {
        builder.addHeader("Authorization", "Basic " + basic);
    }
}
