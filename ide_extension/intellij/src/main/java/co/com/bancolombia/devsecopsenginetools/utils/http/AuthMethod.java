package co.com.bancolombia.devsecopsenginetools.utils.http;

import okhttp3.Request;

public interface AuthMethod {
    void inject(Request.Builder builder);
}
