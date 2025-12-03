package Writer;

import java.io.IOException;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.codahale.shamir.Scheme;

import Writer.timers.ExpiredOperation;
import messages.Metadata;
import messages.Read;
import messages.ReadData;
import messages.ReadMetadata;
import messages.Write;
import messages.WriteAcknowledge;
import messages.WriteMetadata;
import messages.WriteMetadataAcknowledge;
import pt.unl.fct.di.novasys.babel.core.GenericProtocol;
import pt.unl.fct.di.novasys.babel.exceptions.HandlerRegistrationException;
import pt.unl.fct.di.novasys.channel.simpleclientserver.SimpleClientChannel;
import pt.unl.fct.di.novasys.network.data.Host;
import utils.Crypto;

public class Writer extends GenericProtocol {

    public static final String PROTO_NAME = "BestEffortBroadcast";
    public static final short PROTO_ID = 1001;

    public final static String PAR_MYHOST = "membership.myhost";
    public final static String WRITERS = "membership.neighbors";
    public final static String STORAGE = "storage.services";
    public final static String OTHERS = "crypto_names";

    public static final String ADDRESS_KEY = "address";
    public static final String SERVER_PORT_KEY = "server_port";

    public final static short APP_SERVER_PROTO = 300;

    private HashSet<UUID> delivered;
    private List<Host> neighbors;
    private HashMap<Host, PublicKey> publicKeys;

    private Host mySelf;
    private PublicKey myPublicKey;
    private PrivateKey myPrivateKey;
    private KeyStore truststore;
    private String myIdentifier;

    private Map<String, Integer> filesVersions;

    private static final int FILE_SIZE = 200;
    private static final String UPLOAD_DIR = "uploaded_files";

    private int channelID;
    private int[] hostChannels;

    private final Logger logger = LogManager.getLogger(Writer.class);

    //Shamir
    private Scheme scheme;
    private int f;
    private int threshold;
    private List<Host> servers;

    //timer
    private long operation_timeout;
    private long timeoutTimerID;
    public final static String OPERATION_TIMEOUT = "operation_timeout";

    private Map<UUID, List<Host>> pendingAcks;
    public boolean isDoingOp = false;

    public Writer() {
        super(PROTO_NAME, PROTO_ID);

        delivered = new HashSet<>();
        neighbors = new ArrayList<>();
        publicKeys = new HashMap<>();
        pendingAcks = new HashMap<>();

        this.mySelf = null;
        this.myPublicKey = null;
        this.myPrivateKey = null;
        this.truststore = null;
        this.myIdentifier = null;
        this.filesVersions = new HashMap<>();

        this.servers = new ArrayList<>();

        //TRATAR DA PARTE DOS SERVERS
        this.f = 0;
        this.threshold = f + 1;
        this.scheme = null;

        //timer
        this.timeoutTimerID = -1;
        this.operation_timeout = -1;

    }

    @Override
    public void init(Properties props) throws HandlerRegistrationException, IOException {
        myIdentifier = props.getProperty(Crypto.CRYPTO_NAME_KEY);

        this.operation_timeout = Long.parseLong(props.getProperty(OPERATION_TIMEOUT));

        String[] writersList = props.getProperty(WRITERS).split(",");
        for (String s : writersList) {
            String[] e = s.split(":");
            Host candidate = new Host(InetAddress.getByName(e[0]), Short.parseShort(e[1]));
            neighbors.add(candidate);
        }

        String[] hostElements = props.getProperty(PAR_MYHOST).split(":");
        this.mySelf = new Host(InetAddress.getByName(hostElements[0]), Short.parseShort(hostElements[1]));

        String[] storageList = props.getProperty(STORAGE).split(",");
        for (String s : storageList) {
            String[] e = s.split(":");
            Host candidate = new Host(InetAddress.getByName(e[0]), Short.parseShort(e[1]));
            servers.add(candidate);
        }

        try {
            this.myPrivateKey = Crypto.getPrivateKey(myIdentifier, props);
            this.truststore = Crypto.getTruststore(props);
            this.myPublicKey = this.truststore.getCertificate(myIdentifier).getPublicKey();

            String[] nodes = props.getProperty(OTHERS).split(",");

            for (int i = 0; i < nodes.length; i++) {
                PublicKey pk = this.truststore.getCertificate(nodes[i]).getPublicKey();
                publicKeys.put(neighbors.get(i), pk);
                System.out.println("Host: " + neighbors.get(i).toString() + " with key of: " + nodes[i]);
            }

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

        this.f = (servers.size() - 1) / 3;
        this.threshold = f + 1;
        this.scheme = new Scheme(new SecureRandom(), servers.size(), threshold);

        hostChannels = new int[servers.size()];

        for (int i = 0; i < servers.size(); i++) {

            Properties channelProps = new Properties();
            channelProps.put(SimpleClientChannel.ADDRESS_KEY, servers.get(i).getAddress().getHostAddress());
            channelProps.put(SimpleClientChannel.PORT_KEY, String.valueOf(servers.get(i).getPort()));

            hostChannels[i] = createChannel(SimpleClientChannel.NAME, channelProps);

            //Messages
            registerMessageSerializer(hostChannels[i], Write.MESSAGE_ID, Write.serializer);
            registerMessageSerializer(hostChannels[i], WriteAcknowledge.MESSAGE_ID, WriteAcknowledge.serializer);
            registerMessageSerializer(hostChannels[i], WriteMetadata.MESSAGE_ID, WriteMetadata.serializer);
            registerMessageSerializer(hostChannels[i], WriteMetadataAcknowledge.MESSAGE_ID, WriteMetadataAcknowledge.serializer);

            registerMessageSerializer(hostChannels[i], ReadMetadata.MESSAGE_ID, ReadMetadata.serializer);
            registerMessageSerializer(hostChannels[i], Metadata.MESSAGE_ID, Metadata.serializer);
            registerMessageSerializer(hostChannels[i], ReadData.MESSAGE_ID, ReadData.serializer);
            registerMessageSerializer(hostChannels[i], Read.MESSAGE_ID, Read.serializer);

            // Handlers
            registerMessageHandler(hostChannels[i], WriteAcknowledge.MESSAGE_ID, this::uponReceiveWriteAck);
            registerMessageHandler(hostChannels[i], WriteMetadataAcknowledge.MESSAGE_ID, this::uponReceiveMetadataWriteAck);

            registerMessageHandler(hostChannels[i], Metadata.MESSAGE_ID, this::uponReceiveMetadata);
            registerMessageHandler(hostChannels[i], ReadData.MESSAGE_ID, this::uponReceiveReadData);

            openConnection(servers.get(i), hostChannels[i]);
            System.out.println("[WRITER] Estamos a abrir um canal entre: " + servers.get(i).toString() + ": " + channelID);

        }

        registerTimerHandler(ExpiredOperation.TIMER_ID, this::handleExpiredTimer);

    }

    public boolean getIdDoingOp() {
        return isDoingOp;
    }

    public void setIsDoingOp(boolean isDoingOp) {
        this.isDoingOp = isDoingOp;
    }

    public void uploadFile(String filename) {

        if (filename == null || filename.isEmpty()) {
            System.out.println("Usage: UPLOAD <filename>");
            return;
        }
        logger.info("[WRITER] Upload requested for file: " + filename);
        System.out.println("[WRITER] Uploading file: " + filename);

        try {

            Path path = Paths.get(UPLOAD_DIR + "-" + myIdentifier, filename);

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

            byte[] fileBytes = Files.readAllBytes(path);

            //cria uma simetric key
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            SecretKey encryptionKey = keyGen.generateKey();

            //encripta o ficheiro
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, encryptionKey);
            byte[] encryptedFile = cipher.doFinal(fileBytes);

            String fileHash = calculateSHA256(fileBytes);
            System.out.println("[WRITER] File hash: " + fileHash.substring(0, 16) + "...");

            //Parte a chave
            Map<Integer, byte[]> keyShares = splitKey(encryptionKey);

            //Metadata File
            Write msg = new Write(myIdentifier, encryptedFile, filename, filesVersions.get(filename));

            for (int i = 0; i < servers.size(); i++) {
                Path metadataPath = Paths.get(UPLOAD_DIR + "-" + myIdentifier, i + "-metadata-" + filename);

                StringBuilder metadataContent = new StringBuilder();
                metadataContent.append(filesVersions.get(filename)).append("|");
                metadataContent.append(fileHash).append("|");
                metadataContent.append(i + "|");

                byte[] keyShareForThisServer = keyShares.get(i + 1);
                String keyShareBase64 = java.util.Base64.getEncoder().encodeToString(keyShareForThisServer);
                metadataContent.append(keyShareBase64);

                Files.write(metadataPath, metadataContent.toString().getBytes());
                System.out.println("[WRITER] Metadata created: " + metadataPath);
                System.out.println("[WRITER] Metadata content: " + metadataContent.toString().substring(0, 100) + "...");

                sendMessage(hostChannels[i], msg, APP_SERVER_PROTO, servers.get(i), 0);
                System.out.println("Mensagem enviada para: " + servers.get(i).toString());
            }

            List<Host> servers2 = new ArrayList<>(servers);
            pendingAcks.put(msg.getRequestID(), servers2);

            this.setIsDoingOp(true);
            this.timeoutTimerID = setupTimer(new ExpiredOperation(msg.getRequestID(), msg), operation_timeout);
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

    // Timer
    private void handleExpiredTimer(ExpiredOperation expTimer, long l) {
        //TODO PARA QUANDO EXPIRA

    }

    // Writer
    private void uponReceiveWriteAck(WriteAcknowledge wAck, Host host, short i, int i1) {
        System.out.println("Epá cheguei tá fixe");
        List<Host> serversAux = pendingAcks.get(wAck.getRequestID());
        System.out.println("Lista que ainda  tenho: " + serversAux);

        if (serversAux != null) {
            serversAux.remove(host);

            int remaining = serversAux.size();

            System.out.println("[WRITER] ACK from " + host + ", remaining: " + remaining + "/" + servers.size());

            // Quando tiver quorum (n-f respostas)
            if (remaining <= f) {
                System.out.println("[WRITER] Quorum reached! Sending metadata files...");

                clearTimeout();

                String filename = wAck.getFilename();

                try {
                    System.out.println("Severs: " + servers);
                    // Para cada servidor, envia o metadata correspondente

                    UUID requestID = UUID.randomUUID();
                    for (int j = 0; j < servers.size(); j++) {
                        Path metadataPath = Paths.get(UPLOAD_DIR + "-" + myIdentifier, j + "-metadata-" + filename);
                        System.out.println("PATH: " + metadataPath);

                        if (Files.exists(metadataPath)) {
                            //LER BYTES
                            byte[] metadataBytes = Files.readAllBytes(metadataPath);

                            //CONVERTER PARA STRING
                            String metadataContent = new String(metadataBytes, StandardCharsets.UTF_8);

                            //MOSTRAR CONTEÚDO
                            System.out.println("FILE: " + metadataPath.getFileName() + ": " + metadataContent);

                            //PARSE (versão|hash|shareIndex|keyShareBase64)
                            String[] parts = metadataContent.split("\\|");
                            if (parts.length == 4) {
                                int version = Integer.parseInt(parts[0]);
                                String fileHash = parts[1];
                                byte[] fileHashDecored = java.util.Base64.getDecoder().decode(fileHash);
                                int shareIndex = Integer.parseInt(parts[2]);
                                String keyShareB64 = parts[3];

                                Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                                cipher.init(Cipher.ENCRYPT_MODE, myPrivateKey);
                                byte[] encryptedMetadata = cipher.doFinal(metadataBytes);

                                // 5. ENVIAR PARA SERVIDOR
                                WriteMetadata metadataMsg = new WriteMetadata(
                                        filename, version, encryptedMetadata, fileHashDecored, requestID
                                );

                                sendMessage(hostChannels[j], metadataMsg, APP_SERVER_PROTO, servers.get(j), 0);

                                System.out.println("Parsed → v" + version
                                        + " | hash=" + fileHash.substring(0, 16) + "..."
                                        + " | share#" + shareIndex
                                        + " | size=" + keyShareB64.length() + "b");

                                if (j == servers.size() - 1) {
                                    System.out.println("[WRITER] creating timer for metadata");

                                    List<Host> servers2 = new ArrayList<>(servers);
                                    pendingAcks.put(metadataMsg.getRequestID(), servers2);
                                    this.setIsDoingOp(true);
                                    this.timeoutTimerID = setupTimer(new ExpiredOperation(metadataMsg.getRequestID(), metadataMsg), operation_timeout);
                                }

                            }

                        } else {
                            System.err.println("Metadata NOT FOUND: " + metadataPath);
                        }
                    }

                    System.out.println("[WRITER] All metadata files sent!");

                    // Remove do mapa de pendentes
                    pendingAcks.remove(wAck.getRequestID());

                } catch (IOException e) {
                    System.err.println("[WRITER] Error reading/sending metadata files: " + e.getMessage());
                    e.printStackTrace();
                } catch (Exception e) {
                    System.err.println("[WRITER] Error reading/sending metadata files: " + e.getMessage());
                    e.printStackTrace();
                }
            }
        }
    }

    private void uponReceiveMetadataWriteAck(WriteMetadataAcknowledge writeMAck, Host host, short i, int i1) {
        System.out.println("Recebeu Ack final");
        List<Host> serversAux = pendingAcks.get(writeMAck.getRequestID());
        System.out.println("Lista que ainda tenho de metaAck: " + serversAux);

        if (serversAux != null) {
            serversAux.remove(host);

            int remaining = serversAux.size();

            System.out.println("[WRITER] META ACK from " + host + ", remaining: " + remaining + "/" + servers.size());

            if (remaining <= f) {
                String filename = writeMAck.getFilename();
                cleanupMetadataFiles(filename);
                System.out.println("[WRITER] Quorum of metadata reached! Can proceed");
                clearTimeout();
                pendingAcks.remove(writeMAck.getRequestID());
            }

        }
    }

    private void cleanupMetadataFiles(String filename) {
        try {

            for (int i = 0; i < servers.size(); i++) {
                Path metadataPath = Paths.get(UPLOAD_DIR + "-" + myIdentifier, i + "-metadata-" + filename);

                if (Files.exists(metadataPath)) {
                    Files.delete(metadataPath);
                }
            }

        } catch (IOException e) {
            System.err.println("Error during cleanup: " + e.getMessage());
        }
    }

    // Read
    private void uponReceiveMetadata(ReadData read, Host host, short i, int i1) {
    }

    private void uponReceiveReadData(Metadata readM, Host host, short i, int i1) {

    }

    private void clearTimeout() {
        if (timeoutTimerID != -1) {
            cancelTimer(timeoutTimerID);
            this.timeoutTimerID = -1;
        }
        this.setIsDoingOp(false);
    }

    // Shamir
    private Map<Integer, byte[]> splitKey(SecretKey encryptionKey) {
        byte[] keyBytes = encryptionKey.getEncoded();
        return scheme.split(keyBytes);
    }

    private byte[] reconstructKey(Map<Integer, byte[]> shares) {
        if (shares.size() < threshold) {
            throw new IllegalArgumentException(
                    "Needs at least " + threshold + " shares. Received: " + shares.size()
            );
        }

        return scheme.join(shares);
    }

    // Hash
    private String calculateSHA256(byte[] data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(data);

        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
}
