package co.com.bancolombia.devsecopsenginetools.utils;

import lombok.experimental.UtilityClass;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

@UtilityClass
public class Commands {
    public static final int MILLIS = 1000;
    public static final int SECONDS = 60;

    public static void runCommand(String command, Appender appender) throws IOException, InterruptedException {
        runCommand(command, appender, new ProcessBuilder());
    }

    public static void runCommandInDirectory(String command, Appender appender, String directory) throws IOException, InterruptedException {
        runCommand(command, appender, new ProcessBuilder().directory(new File(directory)));
    }

    public static void runCommand(String command, Appender appender, ProcessBuilder processBuilder) throws IOException, InterruptedException {
        long start = System.currentTimeMillis();
        for (String current : command.split("\n")) {
            String[] cmd = current.split(" ");
            processBuilder.command(cmd);
            Process process = processBuilder.start();
            printOutput(appender, process.getInputStream());
            printOutput(appender, process.getErrorStream());
            int exitVal = process.waitFor();
            if (exitVal != 0) {
                throw new IOException("Error running command: " + current + ", exit code: " + exitVal);
            }
        }
        long duration = System.currentTimeMillis() - start;
        appender.success("Command executed successfully in " + formatDuration(duration));
    }

    private static void printOutput(Appender appender, InputStream is) throws IOException {
        BufferedReader reader = new BufferedReader(new InputStreamReader(is));
        String line;
        while ((line = reader.readLine()) != null) {
            appender.onNext(line);
        }
    }

    public interface Appender {
        void onNext(String text);

        void success(String text);

        void error(String text);
    }

    public static String formatDuration(long duration) {
        long minutes = (duration / MILLIS) / SECONDS;
        long seconds = (duration / MILLIS) % SECONDS;
        long milliseconds = duration % MILLIS;
        return String.format("%d min, %d sec, %d ms", minutes, seconds, milliseconds);
    }
}
