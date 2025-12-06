package Writer;

import java.io.IOException;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
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
import messages.Delete;
import messages.DeleteAcknowledge;
import messages.HelloPublicKey;
import messages.ListReply;
import messages.ListRequest;
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
import pt.unl.fct.di.novasys.babel.generic.signed.InvalidSerializerException;
import pt.unl.fct.di.novasys.babel.generic.signed.SignedProtoMessage;
import pt.unl.fct.di.novasys.channel.simpleclientserver.SimpleClientChannel;
import pt.unl.fct.di.novasys.channel.simpleclientserver.events.ServerUpEvent;
import pt.unl.fct.di.novasys.network.data.Host;
import utils.Crypto;
import utils.SignaturesHelper;

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

    private static final int FILE_SIZE = 1024;
    private static final String UPLOAD_DIR = "uploaded_files";

    private int channelID;
    private int[] hostChannels;

    private final Logger logger = LogManager.getLogger(Writer.class);

    // Shamir
    private Scheme scheme;
    private int f;
    private int threshold;
    private List<Host> servers;

    // timer
    private long operation_timeout;
    private long timeoutTimerID;
    public final static String OPERATION_TIMEOUT = "operation_timeout";

    //delete
    private Map<UUID, List<Host>> pendingDeleteAcks;

    //list
    private Map<UUID, ListPendingResponse> pendingListResponses;

    private Map<UUID, List<Host>> pendingAcks;
    private Map<UUID, PendingRead> pendingReads;
    public volatile boolean isDoingOp = false;

    //Latency tests
    private Map<UUID, Long> opStartTimes = new HashMap<>();
    private List<Long> uploadLatencies = new ArrayList<>();
    private List<Long> downloadLatencies = new ArrayList<>();

    public static class PendingRead {

        public final String filename;
        public final UUID requestID;

        public Map<Host, Metadata> metadataResponses = new HashMap<>();
        public Map<Host, ReadData> dataResponses = new HashMap<>();

        public int quorum;
        public Integer selectedVersion = null;
        public String expectedHash = null;

        public PendingRead(String filename, UUID requestID, int quorum) {
            this.filename = filename;
            this.requestID = requestID;
            this.quorum = quorum;
        }
    }

    public static class ListPendingResponse {

        public final String searchPattern;
        public final UUID requestID;
        public final List<String> aggregatedFiles = new ArrayList<>();
        public final List<Host> pendingHosts;

        public ListPendingResponse(String searchPattern, UUID requestID, List<Host> pendingHosts) {
            this.searchPattern = searchPattern;
            this.requestID = requestID;
            this.pendingHosts = pendingHosts;
        }
    }

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
        this.pendingReads = new HashMap<>();

        this.pendingDeleteAcks = new HashMap<>();
        this.pendingListResponses = new HashMap<>();

        // TRATAR DA PARTE DOS SERVERS
        this.f = 0;
        this.threshold = f + 1;
        this.scheme = null;

        // timer
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

            // PARA VERIFICAR SE A KEY ESTA CERTA
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

            // Messages
            registerMessageSerializer(hostChannels[i], Write.MESSAGE_ID, Write.serializer);
            registerMessageSerializer(hostChannels[i], WriteAcknowledge.MESSAGE_ID, WriteAcknowledge.serializer);
            registerMessageSerializer(hostChannels[i], WriteMetadata.MESSAGE_ID, WriteMetadata.serializer);
            registerMessageSerializer(hostChannels[i], WriteMetadataAcknowledge.MESSAGE_ID,
                    WriteMetadataAcknowledge.serializer);

            registerMessageSerializer(hostChannels[i], Delete.MESSAGE_ID, Delete.serializer);
            registerMessageSerializer(hostChannels[i], DeleteAcknowledge.MESSAGE_ID, DeleteAcknowledge.serializer);
            registerMessageSerializer(hostChannels[i], ListRequest.MESSAGE_ID, ListRequest.serializer);
            registerMessageSerializer(hostChannels[i], ListReply.MESSAGE_ID, ListReply.serializer);

            registerMessageSerializer(hostChannels[i], ReadMetadata.MESSAGE_ID, ReadMetadata.serializer);
            registerMessageSerializer(hostChannels[i], Metadata.MESSAGE_ID, Metadata.serializer);
            registerMessageSerializer(hostChannels[i], ReadData.MESSAGE_ID, ReadData.serializer);
            registerMessageSerializer(hostChannels[i], Read.MESSAGE_ID, Read.serializer);

            registerMessageSerializer(hostChannels[i], HelloPublicKey.MESSAGE_ID, HelloPublicKey.serializer);

            // Handlers
            registerMessageHandler(hostChannels[i], WriteAcknowledge.MESSAGE_ID, this::uponReceiveWriteAck);
            registerMessageHandler(hostChannels[i], WriteMetadataAcknowledge.MESSAGE_ID,
                    this::uponReceiveMetadataWriteAck);

            registerMessageHandler(hostChannels[i], Metadata.MESSAGE_ID, this::uponReceiveMetadata);
            registerMessageHandler(hostChannels[i], ReadData.MESSAGE_ID, this::uponReceiveReadData);

            registerChannelEventHandler(hostChannels[i], ServerUpEvent.EVENT_ID, this::uponServerUp);

            registerMessageHandler(hostChannels[i], DeleteAcknowledge.MESSAGE_ID, this::uponReceiveDeleteAck);
            registerMessageHandler(hostChannels[i], ListReply.MESSAGE_ID, this::uponReceiveListReply);

            openConnection(servers.get(i), hostChannels[i]);
            System.out.println(
                    "[WRITER] Estamos a abrir um canal entre: " + servers.get(i).toString() + ": " + channelID);

        }

        registerTimerHandler(ExpiredOperation.TIMER_ID, this::handleExpiredTimer);

    }

    private void uponServerUp(ServerUpEvent event, int channelId) {
        Host server = event.getServer();
        System.out.println("[WRITER] Connection UP to " + server + " on channel " + channelId);

        HelloPublicKey msg = new HelloPublicKey(mySelf, myPublicKey);
        sendMessage(channelId, msg, APP_SERVER_PROTO, server, 0);
        System.out.println("[WRITER] Sent HelloPublicKey to " + server);
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

        UUID uploadOpId = UUID.randomUUID();
        opStartTimes.put(uploadOpId, System.nanoTime());

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

                // Fiz isto para fazer com que o ficheiro mude sempre que mandamos outra versão
                byte[] data = new byte[FILE_SIZE];
                new java.util.Random().nextBytes(data);

                Files.write(path, data);

                filesVersions.put(filename, newVersion);

                System.out.println("[WRITER] File already exists, new version: " + newVersion + " created.");
            }

            byte[] fileBytes = Files.readAllBytes(path);

            // cria uma simetric key
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            SecretKey encryptionKey = keyGen.generateKey();

            // encripta o ficheiro
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, encryptionKey);
            byte[] encryptedFile = cipher.doFinal(fileBytes);

            String fileHash = calculateSHA256(fileBytes);
            System.out.println("[WRITER] File hash: " + fileHash.substring(0, 16) + "...");

            // Parte a chave
            Map<Integer, byte[]> keyShares = splitKey(encryptionKey);

            Write msg = new Write(myIdentifier, encryptedFile, filename, filesVersions.get(filename), uploadOpId);
            List<Host> servers2 = new ArrayList<>(servers);
            pendingAcks.put(msg.getRequestID(), servers2);

            msg.signMessage(myPrivateKey);

            byte[] signAux = SignaturesHelper.generateSignature(this.myIdentifier.getBytes(StandardCharsets.UTF_8),
                    myPrivateKey);

            String sign = Base64.getEncoder().encodeToString(signAux);

            // Metadata File
            for (int i = 0; i < servers.size(); i++) {
                Path metadataPath = Paths.get(UPLOAD_DIR + "-" + myIdentifier, i + "-metadata-" + filename);

                StringBuilder metadataContent = new StringBuilder();
                metadataContent.append(this.myIdentifier).append("|");
                metadataContent.append(sign).append("|");
                metadataContent.append(filesVersions.get(filename)).append("|");
                metadataContent.append(fileHash).append("|");
                metadataContent.append(i + 1).append("|");

                byte[] keyShareForThisServer = keyShares.get(i + 1);
                String keyShareBase64 = java.util.Base64.getEncoder().encodeToString(keyShareForThisServer);
                metadataContent.append(keyShareBase64);

                Files.write(metadataPath, metadataContent.toString().getBytes());
                System.out.println("[WRITER] Metadata created: " + metadataPath);
                System.out
                        .println("[WRITER] Metadata content: " + metadataContent.toString().substring(0, 100) + "...");

                sendMessage(hostChannels[i], msg, APP_SERVER_PROTO, servers.get(i), 0);
                System.out.println("Mensagem enviada para: " + servers.get(i).toString());
            }

            this.setIsDoingOp(true);
            clearTimeout();
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
            System.out.println("Usage: DOWNLOAD <filename> <outputName>");
            return;
        }

        UUID rid = UUID.randomUUID();
        opStartTimes.put(rid, System.nanoTime());

        int quorum = servers.size() - f;
        PendingRead pr = new PendingRead(filename, rid, quorum);
        pendingReads.put(rid, pr);

        System.out.println("[READ] Starting download of " + filename + " with request " + rid);

        ReadMetadata msg = new ReadMetadata(filename, rid);
        try {
            msg.signMessage(myPrivateKey);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        } catch (InvalidSerializerException e) {
            throw new RuntimeException(e);
        }

        for (int i = 0; i < servers.size(); i++) {
            sendMessage(hostChannels[i], msg, APP_SERVER_PROTO, servers.get(i), 0);
        }

        clearTimeout();
        this.timeoutTimerID = setupTimer(new ExpiredOperation(rid, null), operation_timeout);
        this.setIsDoingOp(true);
    }

    // Timer
    private void handleExpiredTimer(ExpiredOperation expTimer, long l) {

        SignedProtoMessage msg = expTimer.getMessage();
        UUID reqID = null;

        if (msg instanceof Write) {
            reqID = ((Write) msg).getRequestID();
        } else if (msg instanceof WriteMetadata) {
            reqID = ((WriteMetadata) msg).getRequestID();
        }

        System.out.println("[WRITER] Operation timed out for request " + reqID);

        if (reqID != null) {
            pendingAcks.remove(reqID);
        }

        clearTimeout();
        this.setIsDoingOp(false);

        System.out.println("[WRITER] Operation aborted. You can type commands again.");
    }

    // Writer
    private void uponReceiveWriteAck(WriteAcknowledge wAck, Host host, short i, int i1) {
        System.out.println("Epá cheguei tá fixe");
        List<Host> serversAux = pendingAcks.get(wAck.getRequestID());

        if (serversAux == null) {
            System.out.println("[WRITER] WriteAck for unknown/cleared request: " + wAck.getRequestID());
            return;
        }

        if (!wAck.isSuccess()) {
            System.out.println("[WRITER] WriteAck do host:  " + host + " deu erro: " + wAck.getMessage());
            return;
        }

        synchronized (serversAux) {
            serversAux.remove(host);
        }

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

                UUID metadataRequestID = wAck.getRequestID();

                pendingAcks.remove(wAck.getRequestID());

                List<Host> serversForMeta = new ArrayList<>(servers);
                pendingAcks.put(metadataRequestID, new ArrayList<>(serversForMeta));

                for (int j = 0; j < servers.size(); j++) {
                    Path metadataPath = Paths.get(UPLOAD_DIR + "-" + myIdentifier, j + "-metadata-" + filename);
                    System.out.println("PATH: " + metadataPath);

                    if (Files.exists(metadataPath)) {
                        // LER BYTES
                        byte[] metadataBytes = Files.readAllBytes(metadataPath);

                        // CONVERTER PARA STRING
                        String metadataContent = new String(metadataBytes, StandardCharsets.UTF_8);

                        // MOSTRAR CONTEÚDO
                        //System.out.println("FILE: " + metadataPath.getFileName() + ": " + metadataContent);
                        // PARSE (versão|hash|shareIndex|keyShareBase64)
                        String[] parts = metadataContent.split("\\|");
                        if (parts.length == 6) {
                            String identifier = parts[0];
                            byte[] sign = Base64.getDecoder().decode(parts[1]);
                            int version = Integer.parseInt(parts[2]);
                            String fileHash = parts[3];
                            byte[] fileHashDecored = java.util.Base64.getDecoder().decode(fileHash);
                            int shareIndex = Integer.parseInt(parts[4]);
                            String keyShareB64 = parts[5];

                            // Encrypt metadata
                            // 5. ENVIAR PARA SERVIDOR
                            WriteMetadata metadataMsg = new WriteMetadata(
                                    filename, version, metadataBytes, fileHashDecored, metadataRequestID);
                            metadataMsg.signMessage(myPrivateKey);
                            sendMessage(hostChannels[j], metadataMsg, APP_SERVER_PROTO, servers.get(j), 0);

                            System.out.println("Parsed → v" + version
                                    + " | hash=" + fileHash.substring(0, 16) + "..."
                                    + " | share#" + shareIndex
                                    + " | size=" + keyShareB64.length() + "b");

                        }

                    } else {
                        System.err.println("Metadata NOT FOUND: " + metadataPath);
                    }
                }

                System.out.println("[WRITER] All metadata files sent!");

                // Setup timer para a fase METADATA
                clearTimeout();
                // Nota: aqui não temos a mensagem concreta, mas passamos um ExpiredOperation
                // com apenas o ID
                this.timeoutTimerID = setupTimer(new ExpiredOperation(metadataRequestID, null), operation_timeout);
                this.setIsDoingOp(true);

            } catch (IOException e) {
                System.err.println("[WRITER] Error reading/sending metadata files: " + e.getMessage());
                e.printStackTrace();
                // fallback de limpeza para não bloquear CLI
                pendingAcks.remove(wAck.getRequestID());
                this.setIsDoingOp(false);
                clearTimeout();
            } catch (Exception e) {
                System.err.println("[WRITER] Error during metadata send: " + e.getMessage());
                e.printStackTrace();
                pendingAcks.remove(wAck.getRequestID());
                this.setIsDoingOp(false);
                clearTimeout();
            }
        }

    }

    private void uponReceiveMetadataWriteAck(WriteMetadataAcknowledge writeMAck, Host host, short i, int i1) {
        System.out.println("Recebeu Ack final");
        List<Host> serversAux = pendingAcks.get(writeMAck.getRequestID());
        System.out.println("Lista que ainda tenho de metaAck: " + serversAux);

        if (serversAux == null) {
            this.setIsDoingOp(false);
            System.out.println("[WRITER] WriteMetadataAck for unknown/cleared request: " + writeMAck.getRequestID());
            return;
        }

        if (!writeMAck.isSuccess()) {
            System.out.println("[WRITER] WriteMAck do host:  " + host + " deu erro: " + writeMAck.getMessage());
            return;
        }

        synchronized (serversAux) {
            serversAux.remove(host);
        }

        int remaining = serversAux.size();

        System.out.println("[WRITER] META ACK from " + host + ", remaining: " + remaining + "/" + servers.size());

        if (remaining <= f) {
            String filename = writeMAck.getFilename();
            cleanupMetadataFiles(filename);
            System.out.println("[WRITER] Quorum of metadata reached! Can proceed");
            clearTimeout();
            pendingAcks.remove(writeMAck.getRequestID());
            this.setIsDoingOp(false);

            UUID reqId = writeMAck.getRequestID();
            Long startTime = opStartTimes.remove(reqId);
            if (startTime != null) {
                long latencyMs = (System.nanoTime() - startTime) / 1_000_000;
                uploadLatencies.add(latencyMs);
                System.out.println("[LATENCY] UPLOAD " + writeMAck.getFilename() + " = " + latencyMs + " ms");
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
    public void uponReceiveMetadata(Metadata msg, Host from, short source, int chan) {

        if (!msg.getSuccess()) {
            System.out.println("[WRITER] Metadata do host:  " + from + " deu erro: " + msg.getMessage());
            return;
        }

        PendingRead pr = pendingReads.get(msg.getRequestID());
        if (pr == null) {
            System.out.println("Teste alfredo");
            return;
        }
        pr.metadataResponses.put(from, msg);

        byte[] identifierToBytes = msg.getIdentifier().getBytes(StandardCharsets.UTF_8);

        try {
            PublicKey keyMsg = this.truststore.getCertificate(msg.getIdentifier()).getPublicKey();
            if (!SignaturesHelper.checkSignature(identifierToBytes, msg.getSignature(), keyMsg)) {
                System.out.println("[READ] O node detentor do ficheiro enviado no read não está correto.");
                return;
            }
        } catch (KeyStoreException | InvalidKeyException | SignatureException | NoSuchAlgorithmException e) {
            e.printStackTrace();
            System.out.println("[READ] Erro ao confirmar node detentor do ficheiro");
        }

        if (pr.metadataResponses.size() >= pr.quorum && pr.selectedVersion == null) {

            Metadata newest = pr.metadataResponses
                    .values()
                    .stream()
                    .max(Comparator.comparingInt(Metadata::getVersion))
                    .orElse(null);

            pr.selectedVersion = newest.getVersion();
            pr.expectedHash = newest.getFileHash();

            System.out.println("[READ] Chosen version " + pr.selectedVersion
                    + " for file " + pr.filename);

            Read rmsg = new Read(pr.filename, pr.selectedVersion, pr.requestID);
            try {
                rmsg.signMessage(myPrivateKey);
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            } catch (InvalidKeyException e) {
                throw new RuntimeException(e);
            } catch (SignatureException e) {
                throw new RuntimeException(e);
            } catch (InvalidSerializerException e) {
                throw new RuntimeException(e);
            }

            for (int i = 0; i < servers.size(); i++) {
                sendMessage(hostChannels[i], rmsg, APP_SERVER_PROTO, servers.get(i), 0);
            }
        }
    }

    public void uponReceiveReadData(ReadData msg, Host from, short source, int chan) {

        PendingRead pr = pendingReads.get(msg.getRequestID());
        if (pr == null) {
            return;
        }

        if (!msg.getSuccess()) {
            System.out.println("[WRITER] Read do host:  " + from + " deu erro: " + msg.getMessage());
            return;
        }

        if (msg.getVersion() != pr.selectedVersion) {
            return;
        }

        pr.dataResponses.put(from, msg);

        if (pr.dataResponses.size() >= pr.quorum) {

            System.out.println("[READ] Received data quorum for version " + pr.selectedVersion);

            // reconstruir file
            finishRead(pr);
        }
    }

    private void finishRead(PendingRead pr) {
        try {

            Map<Integer, byte[]> shares = new HashMap<>();
            for (Metadata m : pr.metadataResponses.values()) {
                if (m.getVersion() == pr.selectedVersion) {
//                    System.out.println("Share index: " + m.getShareIndex());
                    shares.put(m.getShareIndex(), m.getKeyShare());
                }
            }

            byte[] aesKey = this.reconstructKey(shares);

            byte[] encrypted = pr.dataResponses.values().iterator().next().getEncryptedFile();

            byte[] plaintext = decryptAES(encrypted, aesKey);

            String hash = calculateSHA256(plaintext);
            if (!hash.equals(pr.expectedHash)) {
                System.out.println("[READ] ERROR: Hash mismatch! Possible Byzantine server.");
                pendingReads.remove(pr.requestID);
                this.setIsDoingOp(false);
                clearTimeout();
                return;
            }
            Path out = Paths.get(UPLOAD_DIR + "-" + myIdentifier, "download-" + pr.filename);
            if (!Files.exists(out.getParent())) {
                Files.createDirectories(out.getParent());
            }
            Files.write(out, plaintext);
            System.out.println("[READ] File downloaded successfully: " + out.toString());

        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("[READ] Failed to reconstruct file.");
        }
        pendingReads.remove(pr.requestID);

        Long startTime = opStartTimes.remove(pr.requestID);
        if (startTime != null) {
            long latencyMs = (System.nanoTime() - startTime) / 1_000_000;
            downloadLatencies.add(latencyMs);
            System.out.println("[LATENCY] DOWNLOAD " + pr.filename + " = " + latencyMs + " ms");
        }

        this.setIsDoingOp(false);
        clearTimeout();
    }

    //Delete
    public void deleteFile(String filename) {
        if (filename == null || filename.isEmpty()) {
            System.out.println("Usage: DELETE <filename>");
            return;
        }

        System.out.println("[WRITER] Deleting file: " + filename);

        Delete msg = new Delete(filename);

        try {
            msg.signMessage(myPrivateKey);
        } catch (Exception e) {
            System.err.println("[WRITER] Error signing delete message: " + e.getMessage());
            return;
        }

        List<Host> serversCopy = new ArrayList<>(servers);
        pendingDeleteAcks.put(msg.getRequestID(), serversCopy);

        for (int i = 0; i < servers.size(); i++) {
            sendMessage(hostChannels[i], msg, APP_SERVER_PROTO, servers.get(i), 0);
        }

        this.setIsDoingOp(true);
        clearTimeout();
        this.timeoutTimerID = setupTimer(new ExpiredOperation(msg.getRequestID(), msg), operation_timeout);

        System.out.println("[WRITER] Delete request sent for: " + filename);
    }

    private void uponReceiveDeleteAck(DeleteAcknowledge ack, Host from, short i, int i1) {
        List<Host> serversAux = pendingDeleteAcks.get(ack.getRequestID());

        if (serversAux == null) {
            System.out.println("[WRITER] DeleteAck for unknown/cleared request: " + ack.getRequestID());
            return;
        }

        if (!ack.isSuccess()) {
            System.out.println("[WRITER] Delete do host:  " + from + " deu erro: " + ack.getMessage());
            return;
        }

        synchronized (serversAux) {
            serversAux.remove(from);
        }

        int remaining = serversAux.size();
        System.out.println("[WRITER] DELETE ACK from " + from + ", remaining: " + remaining + "/" + servers.size());

        if (remaining <= f) {
            System.out.println("[WRITER] Delete quorum reached for file: " + ack.getFilename());

            // Remove from versions map
            filesVersions.remove(ack.getFilename());

            pendingDeleteAcks.remove(ack.getRequestID());
            clearTimeout();
            this.setIsDoingOp(false);

            System.out.println("[WRITER] File deleted successfully: " + ack.getFilename());
        }
    }

    //List
    public void listFiles(String searchPattern) {
        if (searchPattern == null) {
            searchPattern = "";
        }

        System.out.println("[WRITER] Listing files matching: " + (searchPattern.isEmpty() ? "*" : searchPattern));

        ListRequest msg = new ListRequest(searchPattern);

        try {
            msg.signMessage(myPrivateKey);
        } catch (Exception e) {
            System.err.println("[WRITER] Error signing list message: " + e.getMessage());
            return;
        }

        UUID rid = msg.getRequestID();
        List<Host> serversCopy = new ArrayList<>(servers);
        ListPendingResponse pending = new ListPendingResponse(searchPattern, rid, serversCopy);
        pendingListResponses.put(rid, pending);
//        // Send only to first server (or you can query all for redundancy)
//        sendMessage(hostChannels[0], msg, APP_SERVER_PROTO, servers.get(0), 0);

        for (int i = 0; i < servers.size(); i++) {
            sendMessage(hostChannels[i], msg, APP_SERVER_PROTO, servers.get(i), 0);
        }

        this.setIsDoingOp(true);
        clearTimeout();
        this.timeoutTimerID = setupTimer(new ExpiredOperation(msg.getRequestID(), msg), operation_timeout);
    }

    private void uponReceiveListReply(ListReply response, Host host, short i, int i1) {
        ListPendingResponse pending = pendingListResponses.get(response.getRequestID());

        if (pending == null) {
            System.out.println("[WRITER] ListResponse for unknown/cleared request: " + response.getRequestID());
            return;
        }

        // Adicionar ficheiros sem duplicados
        for (String filename : response.getFilenames()) {
            if (!pending.aggregatedFiles.contains(filename)) {
                pending.aggregatedFiles.add(filename);
            }
        }

        // Remover este host da lista de pendentes (tal como nos outros)
        synchronized (pending.pendingHosts) {
            pending.pendingHosts.remove(host);
        }

        int remaining = pending.pendingHosts.size();
        System.out.println("[WRITER] LIST reply from " + host + ", remaining: " + remaining + "/" + servers.size());

        if (remaining <= f) {
            System.out.println("[WRITER] List quorum reached! Files found:");

            if (pending.aggregatedFiles.isEmpty()) {
                System.out.println("  (no files found)");
            } else {
                pending.aggregatedFiles.sort(String::compareTo);
                for (String filename : pending.aggregatedFiles) {
                    System.out.println("  - " + filename);
                }
            }

            pendingListResponses.remove(response.getRequestID());
            clearTimeout();
            this.setIsDoingOp(false);

            System.out.println("[WRITER] Total: " + pending.aggregatedFiles.size() + " file(s)");
        }
    }

    private void clearTimeout() {
        if (timeoutTimerID != -1) {
            cancelTimer(timeoutTimerID);
            this.timeoutTimerID = -1;
        }
    }

    // Shamir
    private Map<Integer, byte[]> splitKey(SecretKey encryptionKey) {
        byte[] keyBytes = encryptionKey.getEncoded();
        return scheme.split(keyBytes);
    }

    private byte[] reconstructKey(Map<Integer, byte[]> shares) {
        if (shares.size() < threshold) {
            throw new IllegalArgumentException(
                    "Needs at least " + threshold + " shares. Received: " + shares.size());
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

    private byte[] decryptAES(byte[] encrypted, byte[] keyBytes) throws Exception {
        SecretKey key = new javax.crypto.spec.SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(encrypted);
    }

    //Test functions
    public void getResults() {
        System.out.println("\n========== LATENCY STATISTICS ==========");
        printOne("UPLOAD", uploadLatencies);
        printOne("DOWNLOAD", downloadLatencies);
        System.out.println("========================================\n");
    }

    private void printOne(String name, List<Long> values) {
        if (values.isEmpty()) {
            return;
        }
        values.sort(Long::compare);
        double avg = values.stream().mapToLong(Long::longValue).average().orElse(0);
        long p50 = percentile(values, 50);
        long p95 = percentile(values, 95);
        long p99 = percentile(values, 99);

        System.out.printf("%s: avg=%.2f ms, p50=%d ms, p95=%d ms, p99=%d ms (samples=%d)\n",
                name, avg, p50, p95, p99, values.size());
    }

    private long percentile(List<Long> values, int p) {
        if (values.isEmpty()) {
            return 0;
        }
        int idx = (int) Math.ceil(p / 100.0 * values.size()) - 1;
        idx = Math.max(0, Math.min(idx, values.size() - 1));
        return values.get(idx);
    }

    public void clearLatencyStats() {
        opStartTimes.clear();
        uploadLatencies.clear();
        downloadLatencies.clear();
    }

}
