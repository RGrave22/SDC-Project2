package Writer;

import broadcast.messages.BroadcastMessage;
import broadcast.notifications.DeliveryNotification;
import broadcast.requests.BroadcastRequest;
import com.codahale.shamir.Scheme;
import common.events.ChannelAvailable;
import common.events.NeighborDown;
import common.events.NeighborUp;
import membership.staticmembership.message.HelloMessage;
import membership.staticmembership.message.HelloReplyMessage;
import membership.staticmembership.message.ReplyMessage;
import messages.ReadAcknowledge;
import messages.Write;
import messages.WriteAcknowledge;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import pt.unl.fct.di.novasys.babel.core.GenericProtocol;
import pt.unl.fct.di.novasys.babel.exceptions.HandlerRegistrationException;
import pt.unl.fct.di.novasys.babel.generic.ProtoMessage;
import pt.unl.fct.di.novasys.channel.simpleclientserver.SimpleClientChannel;
import pt.unl.fct.di.novasys.channel.tcp.TCPChannel;
import pt.unl.fct.di.novasys.network.data.Host;
import utils.Crypto;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.*;

public class Writer extends GenericProtocol {

    public static final String PROTO_NAME = "BestEffortBroadcast";
    public static final short PROTO_ID = 1001;

    public final static String PAR_MYHOST = "membership.myhost";
    public final static String STORAGE = "storage.services";

    public static final String ADDRESS_KEY = "address";
    public static final String SERVER_PORT_KEY = "server_port";

    private HashSet<UUID> delivered;
    private HashSet<Host> neighbors;
    private HashMap<Host, PublicKey> publicKeys;

    private Host mySelf;
    private PublicKey myPublicKey;
    private PrivateKey myPrivateKey;
    private KeyStore truststore;
    private String myIdentifier;

    private Map<String, Integer> filesVersions;

    private static final int FILE_SIZE = 1024;
    private static final String UPLOAD_DIR = "uploaded_files";

    private int channelID;

    private final Logger logger = LogManager.getLogger(Writer.class);

    //Shamir
    private Scheme scheme;
    private int threshold;
    private List<Host> servers;

    public Writer() {
        super(PROTO_NAME, PROTO_ID);

        delivered = new HashSet<UUID>();
        neighbors = new HashSet<Host>();
        publicKeys = new HashMap<Host, PublicKey>();

        this.mySelf = null;
        this.myPublicKey = null;
        this.myPrivateKey = null;
        this.truststore = null;
        this.myIdentifier = null;
        this.filesVersions = new HashMap<>();

        this.servers = new ArrayList<>();

        //TRATAR DA PARTE DOS SERVERS
        int f = 0;
        this.threshold = f + 1;
        this.scheme = null;

    }

    @Override
    public void init(Properties props) throws HandlerRegistrationException, IOException {
        myIdentifier = props.getProperty(Crypto.CRYPTO_NAME_KEY);

        try {
            this.myPrivateKey = Crypto.getPrivateKey(myIdentifier, props);
            this.truststore = Crypto.getTruststore(props);
            this.myPublicKey = this.truststore.getCertificate(myIdentifier).getPublicKey();

            //PARA VERIFICAR SE A KEY ESTA CERTA
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(myPublicKey.getEncoded());
            StringBuilder hex = new StringBuilder();
            for (byte b : hash) {
                hex.append(String.format("%02x", b));
            }
            logger.info("[WRITER] Public key fingerprint (SHA-256): " + hex);
            System.out.println("[WRITER] Public key fingerprint (SHA-256): " + hex);

        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        } catch (UnrecoverableKeyException e) {
            throw new RuntimeException(e);
        }

        String[] hostElements = props.getProperty(PAR_MYHOST).split(":");
        this.mySelf = new Host(InetAddress.getByName(hostElements[0]), Short.parseShort(hostElements[1]));

        Properties channelProps = new Properties();
//        channelProps.put(TCPChannel.ADDRESS_KEY, props.getProperty(ADDRESS_KEY));
//        channelProps.put(TCPChannel.PORT_KEY, props.getProperty(SERVER_PORT_KEY));
        channelProps.put(SimpleClientChannel.ADDRESS_KEY, props.getProperty(ADDRESS_KEY));
        channelProps.put(SimpleClientChannel.PORT_KEY, props.getProperty(SERVER_PORT_KEY));

        channelID = createChannel(SimpleClientChannel.NAME, channelProps);

        String[] storageList = props.getProperty(STORAGE).split(",");
        for (int i = 0; i < storageList.length; i++) {
            hostElements = storageList[i].split(":");
            Host candidate = new Host(InetAddress.getByName(hostElements[0]), Short.parseShort(hostElements[1]));
            servers.add(candidate);
        }

        int f = (servers.size() - 1) / 3;
        this.threshold = f + 1;
        this.scheme = new Scheme(new SecureRandom(), servers.size(), threshold);

        //Messages
        registerMessageSerializer(channelID, WriteAcknowledge.MESSAGE_ID, WriteAcknowledge.serializer);
        registerMessageSerializer(channelID, ReadAcknowledge.MESSAGE_ID, ReadAcknowledge.serializer);
        registerMessageSerializer(channelID, Write.MESSAGE_ID, Write.serializer);

        registerMessageHandler(channelID, WriteAcknowledge.MESSAGE_ID, this::uponReceiveWriteAck);
        registerMessageHandler(channelID, ReadAcknowledge.MESSAGE_ID, this::uponReceiveReadAck);

        for (Host host : servers) {
            openConnection(host, channelID);
            System.out.println("[WRITER] Estamos a abrir um canal entre: " + host.toString() + ": " + channelID);
            break;
        }
    }

    private void uponReceiveReadAck(ProtoMessage protoMessage, Host host, short i, int i1) {

    }

    private void uponReceiveWriteAck(ProtoMessage protoMessage, Host host, short i, int i1) {

    }

    public void uploadFile(String filename) {
        if (filename == null || filename.isEmpty()) {
            System.out.println("Usage: UPLOAD <filename>");
            return;
        }
        logger.info("[WRITER] Upload requested for file: " + filename);
        System.out.println("[WRITER] Uploading file: " + filename);

        try {
            Path path = Paths.get(UPLOAD_DIR, filename);

            if (!filesVersions.containsKey(filename)) {
                byte[] data = new byte[FILE_SIZE];
                new java.util.Random().nextBytes(data);

                Files.write(path, data);

                filesVersions.put(filename, 1);

                System.out.println("[WRITER] New file created with version 1.");
            } else {
                int currentVersion = filesVersions.get(filename);
                int newVersion = currentVersion + 1;

                //Fiz isto para fazer com que o ficheiro mude sempre que mandamos outra versão
                byte[] data = new byte[FILE_SIZE];
                new java.util.Random().nextBytes(data);

                Files.write(path, data);

                filesVersions.put(filename, newVersion);

                System.out.println("[WRITER] File already exists, new version: " + newVersion + " created.");
            }

            // Ler ficheiro do disco para upload
            byte[] fileBytes = Files.readAllBytes(path);

            // TODO: cifrar, Shamir, enviar mensagens
            Write msg = new Write(myIdentifier, fileBytes, filename);

            for (Host h : servers) {
                sendMessage(channelID, msg, (short) 300, h, 0);
                System.out.println("Mensagem enviada para: " + h.toString());
                break;
            }

            System.out.println("[WRITER] Ready to upload: " + filename);

        } catch (IOException e) {
            logger.error("[WRITER] Error reading/writing file " + filename, e);
            System.out.println("[WRITER] Error reading/writing file: " + e.getMessage());
        } catch (Exception e) {
            logger.error("[WRITER] Error during upload of " + filename, e);
            System.out.println("[WRITER] Error during upload: " + e.getMessage());
        }
    }

    public void downloadFile(String filename) {
        if (filename == null || filename.isEmpty()) {
            System.out.println("Usage: DOWNLOAD <filename>");
            return;
        }
        logger.info("[WRITER] Download requested for file: " + filename);
        System.out.println("[WRITER] Downloading file: " + filename);

        // TODO
    }

    //Shamir
    private Map<Integer, byte[]> splitKey(SecretKey encryptionKey) {
        byte[] keyBytes = encryptionKey.getEncoded();
        return scheme.split(keyBytes);
    }

    public byte[] reconstructKey(Map<Integer, byte[]> shares) {
        if (shares.size() < threshold) {
            throw new IllegalArgumentException(
                    "Needs at least " + threshold + " shares. Received: " + shares.size()
            );
        }

        return scheme.join(shares);
    }
}
