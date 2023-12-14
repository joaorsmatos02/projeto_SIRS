package utils;

import com.google.gson.JsonObject;

import java.io.*;

public class utils {

    public static void writeToFile(File file, Object... objects) {
        for (Object o : objects) {
            if (o instanceof JsonObject) {
                writeObjectStr(file, o.toString());
            } else {
                writeObject(file, o);
            }
        }
    }

    private static void writeObjectStr(File file, String object) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(file))) {
            writer.write(object);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static void writeObject(File file, Object object) {
        try (ObjectOutputStream objectOutputStream = new ObjectOutputStream(new FileOutputStream(file))) {
            objectOutputStream.writeObject(object);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

}
