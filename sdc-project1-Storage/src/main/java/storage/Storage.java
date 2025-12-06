package storage;

import java.io.IOException;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.*;

import messages.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import pt.unl.fct.di.novasys.babel.core.GenericProtocol;
import pt.unl.fct.di.novasys.babel.exceptions.HandlerRegistrationException;
import pt.unl.fct.di.novasys.babel.generic.ProtoMessage;
import pt.unl.fct.di.novasys.babel.generic.signed.InvalidFormatException;
import pt.unl.fct.di.novasys.babel.generic.signed.NoSignaturePresentException;
import pt.unl.fct.di.novasys.channel.simpleclientserver.SimpleServerChannel;
import pt.unl.fct.di.novasys.network.data.Host;
import utils.Crypto;
import utils.SignaturesHelper;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Storage extends GenericProtocol {

    public static final String PROTO_NAME = "BestEffortBroadcast";
    public static final short PROTO_ID = 300;

    public static final short APP_CLIENT_WRITER = 1001;
    public static final short APP_CLIENT_READER = 1100;

    public static final String ADDRESS_KEY = "address";
    public static final String SERVER_PORT_KEY = "server_port";

    public final static String PAR_MYHOST = "membership.myhost";
    public final static String CLIENTS = "client.services";
    public final static String OTHERS = "crypto_names";

    public final static String NEIGHBORS = "membership.neighbors";

    private HashSet<UUID> delivered;
    private List<Host> neighbors;
    private HashMap<Host, PublicKey> publicKeys;

    private Host mySelf;
    private PublicKey myPublicKey;
    private PrivateKey myPrivateKey;

    private int channelID;

    private KeyStore truststore;

    private Map<String, Host> filesAuthors;

    private final Logger logger = LogManager.getLogger(Storage.class);

    public Storage() {
        super(PROTO_NAME, PROTO_ID);

        delivered = new HashSet<UUID>();
        neighbors = new ArrayList<>();
        publicKeys = new HashMap<Host, PublicKey>();

        this.mySelf = null;
        this.myPublicKey = null;
        this.myPrivateKey = null;
        this.truststore = null;
        this.filesAuthors = new HashMap<>();
    }

    @Override
    public void init(Properties props) throws HandlerRegistrationException, IOException {
        String[] hostElements = props.getProperty(PAR_MYHOST).split(":");

        this.mySelf = new Host(InetAddress.getByName(hostElements[0]), Short.parseShort(hostElements[1]));

        Properties channelProps = new Properties();
        channelProps.put(SimpleServerChannel.ADDRESS_KEY, props.getProperty(ADDRESS_KEY));
        channelProps.put(SimpleServerChannel.PORT_KEY, props.getProperty(SERVER_PORT_KEY));

        channelID = createChannel(SimpleServerChannel.NAME, channelProps);

        String[] writersList = props.getProperty(NEIGHBORS).split(",");
        for (String s : writersList) {
            String[] e = s.split(":");
            Host candidate = new Host(InetAddress.getByName(e[0]), Short.parseShort(e[1]));
            neighbors.add(candidate);
        }

        try {
            this.truststore = Crypto.getTruststore(props);
            this.myPublicKey = this.truststore.getCertificate("node1").getPublicKey();

            String[] nodes = props.getProperty(OTHERS).split(",");

            for (int i = 0; i < nodes.length; i++) {
                PublicKey pk = this.truststore.getCertificate(nodes[i]).getPublicKey();
                publicKeys.put(neighbors.get(i), pk);
                System.out.println("Host: " + neighbors.get(i).toString() + " with key of: " + nodes[i]);
            }

        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }

        // Messages
        registerMessageSerializer(channelID, Write.MESSAGE_ID, Write.serializer);
        registerMessageSerializer(channelID, WriteAcknowledge.MESSAGE_ID, WriteAcknowledge.serializer);
        registerMessageSerializer(channelID, WriteMetadata.MESSAGE_ID, WriteMetadata.serializer);
        registerMessageSerializer(channelID, WriteMetadataAcknowledge.MESSAGE_ID, WriteMetadataAcknowledge.serializer);

        registerMessageSerializer(channelID, Delete.MESSAGE_ID, Delete.serializer);
        registerMessageSerializer(channelID, DeleteAcknowledge.MESSAGE_ID, DeleteAcknowledge.serializer);
        registerMessageSerializer(channelID, ListRequest.MESSAGE_ID, ListRequest.serializer);
        registerMessageSerializer(channelID, ListReply.MESSAGE_ID, ListReply.serializer);

        registerMessageSerializer(channelID, ReadMetadata.MESSAGE_ID, ReadMetadata.serializer);
        registerMessageSerializer(channelID, Metadata.MESSAGE_ID, Metadata.serializer);
        registerMessageSerializer(channelID, ReadData.MESSAGE_ID, ReadData.serializer);
        registerMessageSerializer(channelID, Read.MESSAGE_ID, Read.serializer);

        registerMessageSerializer(channelID, HelloPublicKey.MESSAGE_ID, HelloPublicKey.serializer);

        // Handlers
        registerMessageHandler(channelID, Write.MESSAGE_ID, this::uponReceiveWriteMessage);
        registerMessageHandler(channelID, WriteMetadata.MESSAGE_ID, this::uponReceiveWriteMetadataMessage);

        registerMessageHandler(channelID, ReadMetadata.MESSAGE_ID, this::uponReceiveReadMetadataMessage);
        registerMessageHandler(channelID, Read.MESSAGE_ID, this::uponReceiveReadMessage);

        registerMessageHandler(channelID, HelloPublicKey.MESSAGE_ID, this::uponReceiveHello);

        registerMessageHandler(channelID, Delete.MESSAGE_ID, this::uponReceiveDelete);
        registerMessageHandler(channelID, ListRequest.MESSAGE_ID, this::uponReceiveList);
    }

    //Metodo para registo dos clientes.
    private void uponReceiveHello(HelloPublicKey msg, Host host, short i, int i1) {
        System.out.println("Received public key from: " + host.toString());
        publicKeys.put(host, msg.getPublicKey());
    }

    // Write
    private void uponReceiveWriteMessage(Write write, Host host, short sourceProto, int channelID) {
        System.out.println("Received request to upload file: " + write.getFilename());

        try {

            if (!write.checkSignature(publicKeys.get(host))) {
                logger.error("Unauthorized client");
                WriteAcknowledge wAck = new WriteAcknowledge(
                        write.getFilename(),
                        write.getRequestID(),
                        false,
                        this.mySelf,
                        "Unauthorized client");
                sendMessage(channelID, wAck, APP_CLIENT_WRITER, host, 0);
                return;
            }

            String filename = write.getFilename();
            int version = write.getVersion();
            byte[] encryptedFile = write.getEncryptedFile();

            Host h = filesAuthors.get(filename);

            if (h != null && h.getPort() != host.getPort()) {
                System.out.println("Unauthorized, this file does not belong to you");
                return;
            }

            Path fileDir = Paths.get(mySelf.getPort() + "-storage/" + filename);
            Files.createDirectories(fileDir);

            int expectedVersion = getNextExpectedVersion(fileDir);
            if (version != expectedVersion) {
                System.err.println("Incorrect version, expected: " + expectedVersion
                        + ", received: " + version);

                WriteAcknowledge wAck = new WriteAcknowledge(
                        write.getFilename(),
                        write.getRequestID(),
                        false,
                        this.mySelf,
                        "Incorrect version");
                sendMessage(channelID, wAck, APP_CLIENT_WRITER, host, 0);
                return;
            }

            Path valueFile = fileDir.resolve("value-" + version);
            Files.write(valueFile, encryptedFile);

            System.out.println("Stored file: " + write.getFilename() + " on value-" + version
                    + " (size: " + encryptedFile.length + " bytes)");

            WriteAcknowledge wAck = new WriteAcknowledge(
                    write.getFilename(),
                    write.getRequestID(),
                    true,
                    this.mySelf, "");
            sendMessage(channelID, wAck, APP_CLIENT_WRITER, host, 0);

            filesAuthors.put(filename, host);

        } catch (IOException e) {
            System.err.println("Error processing upload: " + e.getMessage());

            WriteAcknowledge wAck = new WriteAcknowledge(
                    write.getFilename(),
                    write.getRequestID(),
                    false,
                    this.mySelf,
                    "Erro desconhecido");
            sendMessage(channelID, wAck, APP_CLIENT_WRITER, host, 0);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    //Auxiliar function to retreive the expected version on the Storage
    private int getNextExpectedVersion(Path fileDir) throws IOException {
        if (!Files.exists(fileDir)) {
            return 1;
        }

        int maxVersion = 0;

        try (DirectoryStream<Path> stream = Files.newDirectoryStream(fileDir, "value-*")) {
            for (Path file : stream) {
                String fileName = file.getFileName().toString();

                String versionStr = fileName.substring("value-".length());
                try {
                    int version = Integer.parseInt(versionStr);
                    maxVersion = Math.max(maxVersion, version);
                } catch (NumberFormatException e) {
                    System.err.println("Invalid file: " + fileName);
                }
            }
        }

        return maxVersion + 1;
    }

    private void uponReceiveWriteMetadataMessage(WriteMetadata writeM, Host host, short sourceProto, int channelID) {
        System.out.println("Received WriteMetadata for file: " + writeM.getFilename() + "from Host: " + host.toString());

        try {

            if (!writeM.checkSignature(publicKeys.get(host))) {
                logger.error("Unauthorized client");
                WriteMetadataAcknowledge wAck = new WriteMetadataAcknowledge(
                        writeM.getFilename(),
                        false,
                        this.mySelf,
                        writeM.getRequestID(),
                        "Unauthorized client");
                sendMessage(channelID, wAck, APP_CLIENT_WRITER, host, 0);
                return;
            }

            String filename = writeM.getFilename();
            int version = writeM.getVersion();
            byte[] metadataBytes = writeM.getFileBytes();

            Path fileDir = Paths.get(mySelf.getPort() + "-storage/" + filename);
            if (!Files.exists(fileDir)) {
                System.err.println("Directory: " + fileDir + "doesn't exist");
                WriteMetadataAcknowledge nack = new WriteMetadataAcknowledge(
                        filename, false, mySelf, writeM.getRequestID(),
                        "Directory doesn't exist");
                sendMessage(channelID, nack, APP_CLIENT_WRITER, host, 0);
                return;
            }

            Path metadataFile = fileDir.resolve("metadata");
            Files.write(metadataFile, metadataBytes);

            System.out.println("Metadata changed (size: " + metadataBytes.length + " bytes)");

            WriteMetadataAcknowledge ack = new WriteMetadataAcknowledge(
                    filename, true, mySelf, writeM.getRequestID(), "");
            sendMessage(channelID, ack, APP_CLIENT_WRITER, host, 0);

        } catch (IOException e) {
            System.err.println("Error processing WriteMetadata: " + e.getMessage());

            WriteMetadataAcknowledge nack = new WriteMetadataAcknowledge(
                    writeM.getFilename(), false, mySelf, writeM.getRequestID(), "Erro desconhecido");
            sendMessage(channelID, nack, APP_CLIENT_WRITER, host, 0);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (InvalidFormatException e) {
            throw new RuntimeException(e);
        } catch (NoSignaturePresentException e) {
            throw new RuntimeException(e);
        }
    }

    // Read
    private void uponReceiveReadMetadataMessage(ReadMetadata readM, Host host, short sourceProto, int channelID) {
        System.out.println("Received ReadMetadata for file: " + readM.getFilename());
        try {

            if (!readM.checkSignature(publicKeys.get(host))) {
                logger.error("Unauthorized client");
                Metadata metaMsg = new Metadata(
                        readM.getFilename(),
                        0,
                        "",
                        0,
                        new byte[0],
                        readM.getRequestID(),
                        "",
                        new byte[0],
                        false,
                        "Unauthorized client");
                sendMessage(channelID, metaMsg, APP_CLIENT_WRITER, host, 0);
                return;
            }

            String filename = readM.getFilename();
            Path fileDir = Paths.get(mySelf.getPort() + "-storage/" + filename);

            if (!Files.exists(fileDir)) {
                System.err.println("File directory does not exist: " + fileDir);
                Metadata metaMsg = new Metadata(
                        readM.getFilename(),
                        0,
                        "",
                        0,
                        new byte[0],
                        readM.getRequestID(),
                        "",
                        new byte[0],
                        false,
                        "File directory does not exist");
                sendMessage(channelID, metaMsg, APP_CLIENT_WRITER, host, 0);
                return;
            }

            Path metadataFile = fileDir.resolve("metadata");
            if (!Files.exists(metadataFile)) {
                System.err.println("Metadata file not found for " + filename);
                Metadata metaMsg = new Metadata(
                        readM.getFilename(),
                        0,
                        "",
                        0,
                        new byte[0],
                        readM.getRequestID(),
                        "",
                        new byte[0],
                        false,
                        "Metadata file not found");
                sendMessage(channelID, metaMsg, APP_CLIENT_WRITER, host, 0);
                return;
            }

            byte[] metadataBytes = Files.readAllBytes(metadataFile);
            String[] parts = new String(metadataBytes, StandardCharsets.UTF_8).split("\\|");
            if (parts.length != 6) {
                System.err.println("Metadata format invalid for " + filename);
                Metadata metaMsg = new Metadata(
                        readM.getFilename(),
                        0,
                        "",
                        0,
                        new byte[0],
                        readM.getRequestID(),
                        "",
                        new byte[0],
                        false,
                        "Metadata format invalid");
                sendMessage(channelID, metaMsg, APP_CLIENT_WRITER, host, 0);
                return;
            }

            String identifier = parts[0];
            byte[] sign = Base64.getDecoder().decode(parts[1]);
            int version = Integer.parseInt(parts[2]);
            String fileHash = parts[3];
            int shareIndex = Integer.parseInt(parts[4]);
            byte[] keyShare = Base64.getDecoder().decode(parts[5]);

            Metadata metaMsg = new Metadata(
                    readM.getFilename(),
                    version,
                    fileHash,
                    shareIndex,
                    keyShare,
                    readM.getRequestID(),
                    identifier,
                    sign,
                    true,
                    "");

            sendMessage(channelID, metaMsg, APP_CLIENT_WRITER, host, 0);
            System.out.println("Sent Metadata for " + filename + " to " + host);

        } catch (IOException e) {
            System.err.println("Error reading metadata: " + e.getMessage());
            Metadata metaMsg = new Metadata(
                    readM.getFilename(),
                    0,
                    "",
                    0,
                    new byte[0],
                    readM.getRequestID(),
                    "",
                    new byte[0],
                    false,
                    e.getMessage());
            sendMessage(channelID, metaMsg, APP_CLIENT_WRITER, host, 0);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private void uponReceiveReadMessage(Read read, Host host, short sourceProto, int channelID) {
        System.out.println("Received Read for file: " + read.getFilename());
        try {

            String filename = read.getFilename();
            int requestedVersion = read.getVersion();

            if (!read.checkSignature(publicKeys.get(host))) {
                logger.error("Unauthorized client");
                ReadData dataMsg = new ReadData(filename, requestedVersion, new byte[0], read.getRequestID(), false, "Unauthorized client");
                sendMessage(channelID, dataMsg, APP_CLIENT_WRITER, host, 0);
                return;
            }

            Path valueFile = Paths.get(mySelf.getPort() + "-storage/" + filename, "value-" + requestedVersion);

            if (!Files.exists(valueFile)) {
                System.err.println("Value file does not exist: " + valueFile);
                ReadData dataMsg = new ReadData(filename, requestedVersion, new byte[0], read.getRequestID(), false, "Value file does not exist");
                sendMessage(channelID, dataMsg, APP_CLIENT_WRITER, host, 0);
                return;
            }

            byte[] encryptedFile = Files.readAllBytes(valueFile);
            ReadData dataMsg = new ReadData(filename, requestedVersion, encryptedFile, read.getRequestID(), true, "");
            sendMessage(channelID, dataMsg, APP_CLIENT_WRITER, host, 0);

            System.out.println("Sent ReadData for " + filename + " to " + host);
        } catch (IOException e) {
            System.err.println("Error reading file: " + e.getMessage());
            ReadData dataMsg = new ReadData(read.getFilename(), 0, new byte[0], read.getRequestID(), false, e.getMessage());
            sendMessage(channelID, dataMsg, APP_CLIENT_WRITER, host, 0);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // Delete
    private void uponReceiveDelete(Delete delete, Host host, short sourceProto, int channelID) {
        System.out.println("Received Delete for file: " + delete.getFilename());

        try {

            if (!delete.checkSignature(publicKeys.get(host))) {
                logger.error("Unauthorized client");
                DeleteAcknowledge nack = new DeleteAcknowledge(
                        delete.getFilename(),
                        delete.getRequestID(),
                        false,
                        "Unauthorized client"
                );
                sendMessage(channelID, nack, APP_CLIENT_WRITER, host, 0);
                return;
            }

            String filename = delete.getFilename();

            // Verificar se o cliente que está a apagar é o autor original
            Host author = filesAuthors.get(filename);
            if (author != null && author.getPort() != host.getPort()) {
                System.err.println("Delete rejected: client is not the file author");
                DeleteAcknowledge nack = new DeleteAcknowledge(
                        filename,
                        delete.getRequestID(),
                        false,
                        "Delete rejected: client is not the file author"
                );
                sendMessage(channelID, nack, APP_CLIENT_WRITER, host, 0);
                return;
            }

            Path fileDir = Paths.get(mySelf.getPort() + "-storage/" + filename);

            boolean success = deleteDirectory(fileDir);

            if (success) {
                filesAuthors.remove(filename);
                System.out.println("Successfully deleted file directory: " + fileDir);
            }

            DeleteAcknowledge ack = new DeleteAcknowledge(
                    filename,
                    delete.getRequestID(),
                    success,
                    "Error trying to delete file"
            );
            sendMessage(channelID, ack, APP_CLIENT_WRITER, host, 0);

            System.out.println("Sent DeleteAcknowledge for " + filename + " to " + host);

        } catch (Exception e) {
            System.err.println("Unexpected error in Delete handler: " + e.getMessage());
            e.printStackTrace();
        }
    }

    // List
    private void uponReceiveList(ListRequest listReq, Host host, short sourceProto, int channelID) {
        System.out.println("Received ListRequest with pattern: " + listReq.getSearchPattern());

        try {

            if (!listReq.checkSignature(publicKeys.get(host))) {
                logger.error("Unauthorized client");
                return;
            }

            String searchPattern = listReq.getSearchPattern();
            List<String> matchingFiles = new ArrayList<>();

            Path storageDir = Paths.get(mySelf.getPort() + "-storage");

            if (Files.exists(storageDir) && Files.isDirectory(storageDir)) {
                try (DirectoryStream<Path> stream = Files.newDirectoryStream(storageDir)) {
                    for (Path entry : stream) {
                        if (Files.isDirectory(entry)) {
                            String filename = entry.getFileName().toString();

                            if (searchPattern.isEmpty() || filename.contains(searchPattern)) {
                                Path metadataFile = entry.resolve("metadata");
                                if (Files.exists(metadataFile)) {
                                    matchingFiles.add(filename);
                                }
                            }
                        }
                    }
                }
            }

            System.out.println("Found " + matchingFiles.size() + " matching files");

            ListReply reply = new ListReply(listReq.getRequestID(), matchingFiles);
            sendMessage(channelID, reply, APP_CLIENT_WRITER, host, 0);

            System.out.println("Sent ListReply to " + host + " with " + matchingFiles.size() + " files");

        } catch (IOException e) {
            System.err.println("Error listing files: " + e.getMessage());

            try {
                ListReply emptyReply = new ListReply(listReq.getRequestID(), new ArrayList<>());
                sendMessage(channelID, emptyReply, APP_CLIENT_WRITER, host, 0);
            } catch (Exception ex) {
                System.err.println("Error sending empty ListReply: " + ex.getMessage());
            }
        } catch (Exception e) {
            System.err.println("Unexpected error in List handler: " + e.getMessage());
            e.printStackTrace();
        }
    }

    //Aux function to delete the file directory
    private boolean deleteDirectory(Path directory) {
        try {
            if (!Files.exists(directory)) {
                System.err.println("Directory does not exist: " + directory);
                return true;
            }

            Files.walk(directory)
                    .sorted(Comparator.reverseOrder())
                    .forEach(path -> {
                        try {
                            Files.delete(path);
                        } catch (IOException e) {
                            System.err.println("Error deleting: " + path + " - " + e.getMessage());
                        }
                    });

            return true;

        } catch (IOException e) {
            System.err.println("Error walking directory: " + e.getMessage());
            return false;
        }
    }

}
