package co.com.bancolombia.devsecopsenginetools.utils.variables;

import co.com.bancolombia.devsecopsenginetools.configuration.ProjectSettings;

import java.util.List;

public interface VariableProvider {
    List<Variable> getVariables();
}
