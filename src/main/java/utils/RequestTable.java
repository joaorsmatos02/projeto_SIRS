package utils;

import com.google.gson.JsonObject;

import java.util.*;

public class RequestTable {

    private static final Set<String> table = new HashSet<>();

    private static final Timer timer = new Timer();

    private static final long EXPIRATION_TIME_MILLIS = 10000;

    public static void addEntry(String value) {
        table.add(value);
        timer.schedule(new TimerTask() {
            @Override
            public void run() {
                table.remove(value);            }
        }, EXPIRATION_TIME_MILLIS);
    }

    public static boolean hasEntry(String value) {
        System.out.println(table);
        return table.contains(value);
    }

}
