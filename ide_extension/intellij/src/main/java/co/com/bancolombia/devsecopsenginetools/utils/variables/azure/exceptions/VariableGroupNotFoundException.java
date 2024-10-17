package co.com.bancolombia.devsecopsenginetools.utils.variables.azure.exceptions;

public class VariableGroupNotFoundException extends RuntimeException {
    public VariableGroupNotFoundException(String message) {
        super(message);
    }
}
