package co.com.bancolombia.devsecopsenginetools.utils.variables;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class Variable {
    private String name;
    private String value;
}
