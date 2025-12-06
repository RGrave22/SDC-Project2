
import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.security.GeneralSecurityException;
import java.util.*;

import Writer.Writer;
import pt.unl.fct.di.novasys.babel.core.Babel;
import pt.unl.fct.di.novasys.babel.exceptions.HandlerRegistrationException;
import pt.unl.fct.di.novasys.babel.exceptions.InvalidParameterException;
import pt.unl.fct.di.novasys.babel.exceptions.ProtocolAlreadyExistsException;

public class Main {

    // Sets the log4j (logging library) configuration file and forces IPV4
    static {
        System.setProperty("log4j.configurationFile", "log4j2.xml");
        System.setProperty("java.net.preferIPv4Stack", "true");
    }

    public static final String ADDRESS_KEY = "address";

    public static final String WRITER = "writer";
    public static final String MYSELF = "membership.myhost";

    public static final void main(String[] args) throws IOException, InvalidParameterException, ProtocolAlreadyExistsException, HandlerRegistrationException, GeneralSecurityException {
        Properties props = Babel.loadConfig(Arrays.copyOfRange(args, 0, args.length), "babel-conf.txt");

        if (props.containsKey("interface")) {
            String address = Main.getAddress(props.getProperty("interface"));
            if (address == null) {
                return;
            }
            props.put(ADDRESS_KEY, address);
        }

        String writer = props.getProperty(WRITER);
        String mySelf = props.getProperty(MYSELF);

        Babel babel = Babel.getInstance();

//        if(mySelf.equals(writer)){
        Writer w = new Writer();
        babel.registerProtocol(w);
        w.init(props);
        babel.start();
        System.err.println("Babel has started...");

        Scanner scanner = new java.util.Scanner(System.in);

        while (true) {

            while (w.getIdDoingOp()) {
                try {
                    Thread.sleep(100);
                } catch (InterruptedException e) {
                }
            }

            if (!w.getIdDoingOp()) {
                System.out.print("> ");
                String input = scanner.nextLine().trim();
                String[] cmd = input.split("\\s+", 2);
                String command = cmd[0].toUpperCase();
                String argument = (cmd.length > 1) ? cmd[1] : "";

                switch (command) {
                    case "UPLOAD":
                        w.uploadFile(argument);
                        break;
                    case "DOWNLOAD":
                        w.downloadFile(argument);
                        break;
                    case "DELETE":
                        w.deleteFile(argument);
                        break;
                    case "LIST":
                        w.listFiles(argument);
                        break;
                    case "QUIT":
                        System.out.println("Leaving...");
                        System.exit(0);
                        break;
                    case "TEST":
                        runTest(Integer.parseInt(argument), w);

                    default:
                        System.out.println("Unknown Command: " + command);
                }
            }
        }
    }


    public static void runTest(int numOps, Writer w) {
        System.out.println("╔════════════════════════════════════════╗");
        System.out.println("║   TEST: " + numOps + " operations    ║");
        System.out.println("╚════════════════════════════════════════╝");

        new Thread(() -> {
            try {
                Random r = new Random(System.currentTimeMillis());

                List<String> uploadedFiles = new ArrayList<>();

                for (int i = 0; i < numOps; i++) {
                    while (w.getIdDoingOp()) {
                        Thread.sleep(100);
                    }

                    String filename = "test_file_" + r.nextInt(1000);
                    float val = r.nextFloat();

                    if(val <= 0.2 || uploadedFiles.isEmpty()) {
                        w.uploadFile(filename);
                        uploadedFiles.add(filename);
                    }else if(val<= 0.4){
                        filename = uploadedFiles.get(r.nextInt(uploadedFiles.size()));
                        w.uploadFile(filename);
                    } else {
                        filename = uploadedFiles.get(r.nextInt(uploadedFiles.size()));
                        w.downloadFile(filename);
                    }

                    Thread.sleep(200);
                }

                while (w.getIdDoingOp()) {
                    Thread.sleep(100);
                }

                System.out.println("\n╔════════════════════════════════════════╗");
                System.out.println("║   TEST COMPLETED                      ║");
                System.out.println("╚════════════════════════════════════════╝\n");

                w.getResults();
                w.clearLatencyStats();

                System.out.print("\n> ");

            } catch (Exception e) {
                System.err.println("[TEST] Error: " + e.getMessage());
                e.printStackTrace();
            }
        }).start();
    }


    private static String getAddress(String inter) throws SocketException {
        NetworkInterface byName = NetworkInterface.getByName(inter);
        if (byName == null) {
            System.err.println("No interface named " + inter);
            return null;
        }
        Enumeration<InetAddress> addresses = byName.getInetAddresses();
        InetAddress currentAddress;
        while (addresses.hasMoreElements()) {
            currentAddress = addresses.nextElement();
            if (currentAddress instanceof Inet4Address) {
                return currentAddress.getHostAddress();
            }
        }
        System.err.println("No ipv4 found for interface " + inter);
        return null;
    }
}
