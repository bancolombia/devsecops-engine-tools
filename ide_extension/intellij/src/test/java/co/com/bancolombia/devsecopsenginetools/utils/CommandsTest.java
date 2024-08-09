package co.com.bancolombia.devsecopsenginetools.utils;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class CommandsTest {

    @Mock
    private ProcessBuilder processBuilder;
    @Mock
    private Commands.Appender appender;
    @Mock
    private Process process;

    @Test
    public void shouldRunCommand() throws IOException, InterruptedException {
        // Arrange
        String command = "echo 'Hello World'";
        String output = "Hello World";
        when(processBuilder.start()).thenReturn(process);
        when(process.getInputStream()).thenReturn(new ByteArrayInputStream(output.getBytes()));
        when(process.getErrorStream()).thenReturn(new ByteArrayInputStream("".getBytes()));
        when(process.waitFor()).thenReturn(0);
        // Act
        Commands.runCommand(command, appender, processBuilder);
        // Assert
        verify(appender).onNext(output);
        verify(appender, times(1)).onNext(anyString());
        verify(appender, times(1)).success(anyString());
    }

    @Test
    public void shouldFail() throws IOException, InterruptedException {
        // Arrange
        String command = "echo 'Hello World'";
        String output = "Hello World";
        when(processBuilder.start()).thenReturn(process);
        when(process.getInputStream()).thenReturn(new ByteArrayInputStream(output.getBytes()));
        when(process.getErrorStream()).thenReturn(new ByteArrayInputStream("".getBytes()));
        when(process.waitFor()).thenReturn(-1);
        // Assert
        assertThrows(IOException.class, () ->
                // Act
                Commands.runCommand(command, appender, processBuilder));
    }
}
