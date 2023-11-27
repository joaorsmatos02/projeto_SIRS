package utils;

import com.google.gson.JsonObject;

import java.util.*;

public class RequestTable {

    private static final Set<JsonObject> table = new HashSet<>();

    private static final Timer timer = new Timer();

    private static final long EXPIRATION_TIME_MILLIS = 20000;

    public static void addEntry(JsonObject value) {
        table.add(value);
        timer.schedule(new TimerTask() {
            @Override
            public void run() {
                table.remove(value);            }
        }, EXPIRATION_TIME_MILLIS);
    }

    public static boolean hasEntry(JsonObject value) {
        return table.contains(value);
    }

}
