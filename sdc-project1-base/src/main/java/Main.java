
import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Properties;
import java.util.Scanner;

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
                        //TODO
                        break;
                    case "LIST":
                        //TODO
                        break;
                    case "QUIT":
                        System.out.println("Leaving...");
                        System.exit(0);
                        break;
                    default:
                        System.out.println("Unknown Command: " + command);
                }
            }
        }

//        }else{
//            Reader r = new Reader();
//            babel.registerProtocol(r);
//            r.init(props);
//            babel.start();
//            System.err.println("Babel has started...");
//        }
//		DistributedLogManager dlm = new DistributedLogManager();
//		ReplicationProtocolPlaceholder rep = new ReplicationProtocolPlaceholder();
//		CrashFaultReliableBroadcastProtocol bcast = new CrashFaultReliableBroadcastProtocol();
        //To simplify lets use this protocol again
//		StaticMembershipProtocol smp = new StaticMembershipProtocol();
//		babel.registerProtocol(dlm);
//		babel.registerProtocol(rep);
//		babel.registerProtocol(bcast);
//		babel.registerProtocol(smp);
//		dlm.init(props);
//		rep.init(props);
//		bcast.init(props);
//		smp.init(props);
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
