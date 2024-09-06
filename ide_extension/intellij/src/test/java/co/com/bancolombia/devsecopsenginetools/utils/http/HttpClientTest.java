package co.com.bancolombia.devsecopsenginetools.utils.http;

import lombok.Data;
import okhttp3.Call;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.ResponseBody;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.io.IOException;

import static okhttp3.MediaType.get;
import static okhttp3.Protocol.HTTP_1_1;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class HttpClientTest {
    @Mock
    private OkHttpClient client;
    @Mock
    private Call call;
    private HttpClient httpClient;

    @Before
    public void setup() {
        httpClient = new HttpClient(client);
    }

    @Test
    public void shouldGetResponse() throws IOException {
        Response mockResponse = new Response.Builder()
                .request(new Request.Builder().url("https://sampleurl").build())
                .protocol(HTTP_1_1)
                .code(200)
                .message("OK")
                .body(ResponseBody.create("{\"name\":\"name\",\"age\":20}", get("application/json")))
                .build();
        // Arrange
        when(client.newCall(any())).thenReturn(call);
        when(call.execute()).thenReturn(mockResponse);
        // Act
        SampleModelTest response = httpClient.get("https://sampleurl", SampleModelTest.class,
                new BasicAuthMethod("test", "test"));
        // Assert
        assertEquals("name", response.getName());
        assertEquals(20, response.getAge());
    }


    @Test
    public void shouldGetNullWhenResponseFailed() throws IOException {
        Response mockResponse = new Response.Builder()
                .request(new Request.Builder().url("https://sampleurl").build())
                .protocol(HTTP_1_1)
                .code(400)
                .message("Bad Request")
                .body(ResponseBody.create("{\"error\":\"some\"}", get("application/json")))
                .build();
        // Arrange
        when(client.newCall(any())).thenReturn(call);
        when(call.execute()).thenReturn(mockResponse);
        // Act
        SampleModelTest response = httpClient.get("https://sampleurl", SampleModelTest.class);
        // Assert
        assertNull(response);
    }


    @Test(expected = IOException.class)
    public void shouldHandleError() {
        HttpClient realClient = new HttpClient();
        realClient.get("http://localhost:8080", SampleModelTest.class);
    }

    @Data
    public static class SampleModelTest {
        private String name;
        private int age;
    }
}
