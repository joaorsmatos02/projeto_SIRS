import java.util.Scanner;

public class Main {

    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);

        System.out.println("Welcome to BlingBank!");
        printHelp();
        String line = "";

        while (!(line = sc.nextLine()).equals("exit")) {
            String[] command = line.split(" ");
            switch(command[0]) {
                // ...
            }
        }
    }

    private static void printHelp() {

    }

}
