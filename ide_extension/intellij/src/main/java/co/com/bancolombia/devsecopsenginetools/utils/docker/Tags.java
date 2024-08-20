package co.com.bancolombia.devsecopsenginetools.utils.docker;

import lombok.Data;

import java.util.List;

@Data
public class Tags {
    private List<Tag> results;

    @Data
    public static class Tag {
        private String name;
    }
}
