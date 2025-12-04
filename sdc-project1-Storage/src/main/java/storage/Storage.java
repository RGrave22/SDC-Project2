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
import java.util.List;

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

        //Messages
        registerMessageSerializer(channelID, Write.MESSAGE_ID, Write.serializer);
        registerMessageSerializer(channelID, WriteAcknowledge.MESSAGE_ID, WriteAcknowledge.serializer);
        registerMessageSerializer(channelID, WriteMetadata.MESSAGE_ID, WriteMetadata.serializer);
        registerMessageSerializer(channelID, WriteMetadataAcknowledge.MESSAGE_ID, WriteMetadataAcknowledge.serializer);

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

    }

    private void uponReceiveHello(HelloPublicKey msg, Host host, short i, int i1) {
        System.out.println("Recebemos a public key do: " + msg.getHost().toString() + " : " + host.toString());
        publicKeys.put(host, msg.getPublicKey());
    }

    // Write
    private void uponReceiveWriteMessage(Write write, Host host, short sourceProto, int channelID) {
        System.out.println("[STORAGE] RECEBI WRITE para " + write.getFilename());

        try {

            if(!write.checkSignature(publicKeys.get(host))){
                logger.error("[STORAGE] ERROR CHECKING PUBLIC KEY");
                WriteAcknowledge wAck = new WriteAcknowledge(
                        write.getFilename(),
                        write.getRequestID(),
                        false,
                        this.mySelf
                );
                sendMessage(channelID, wAck, APP_CLIENT_WRITER, host, 0);
                return;
            }

            System.out.println("[STORAGE] SIGNATURE OKOKOKOKOK");
            String filename = write.getFilename();
            int version = write.getVersion();
            byte[] encryptedFile = write.getEncryptedFile();

            // 1. Criar diretório filename (se não existir)
            Path fileDir = Paths.get(mySelf.getPort() + "-storage/" + filename);
            Files.createDirectories(fileDir);
            System.out.println("Criada diretório: " + fileDir);

            int expectedVersion = getNextExpectedVersion(fileDir);
            if (version != expectedVersion) {
                System.err.println("Versão incorreta! Esperada: " + expectedVersion
                        + ", Recebida: " + version);

                // Responder NACK por versão incorreta
                WriteAcknowledge wAck = new WriteAcknowledge(
                        write.getFilename(),
                        write.getRequestID(),
                        false,
                        this.mySelf
                );
                sendMessage(channelID, wAck, APP_CLIENT_WRITER, host, 0);
                return;
            }

            // 2. Guardar ficheiro como value-<versão>
            Path valueFile = fileDir.resolve("value-" + version);
            Files.write(valueFile, encryptedFile);

            System.out.println("Guardado value-" + version
                    + " (size: " + encryptedFile.length + " bytes)");

            // 3. Responder ACK
            WriteAcknowledge wAck = new WriteAcknowledge(
                    write.getFilename(),
                    write.getRequestID(),
                    true,
                    this.mySelf
            );
            System.out.println("ESTA È A PUTA: " + wAck.getRequestID());
            sendMessage(channelID, wAck, APP_CLIENT_WRITER, host, 0);
            System.out.println("FODASE");

        } catch (IOException e) {
            System.err.println("Erro ao processar Write: " + e.getMessage());

            // Responder NACK
            WriteAcknowledge wAck = new WriteAcknowledge(
                    write.getFilename(),
                    write.getRequestID(),
                    false,
                    this.mySelf
            );
            sendMessage(channelID, wAck, APP_CLIENT_WRITER, host, 0);
        } catch (Exception e) {
            System.out.println("DEU MERDA: " + e.getMessage());
            throw new RuntimeException(e);
        }
    }

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
                    System.err.println("Ficheiro com nome inválido: " + fileName);
                }
            }
        }

        return maxVersion + 1;
    }

    private void uponReceiveWriteMetadataMessage(WriteMetadata writeM, Host host, short sourceProto, int channelID) {
        System.out.println("[STORAGE] RECEBI WriteMetadata para " + writeM.getFilename() + "do Host: " + host.toString());



        try {

            if(!writeM.checkSignature(publicKeys.get(host))){
                logger.error("[STORAGE] ERROR CHECKING PUBLIC KEY");
                WriteMetadataAcknowledge wAck = new WriteMetadataAcknowledge(
                        writeM.getFilename(),
                        false,
                        this.mySelf,
                        writeM.getRequestID()
                );
                sendMessage(channelID, wAck, APP_CLIENT_WRITER, host, 0);
                return;
            }

            String filename = writeM.getFilename();
            int version = writeM.getVersion();
            byte[] metadataBytes = writeM.getFileBytes();


            // 1. Verificar se diretório existe
            Path fileDir = Paths.get(mySelf.getPort() + "-storage/" + filename);
            if (!Files.exists(fileDir)) {
                System.err.println("Diretório não existe: " + fileDir);
                // NACK se diretório não existir
                WriteMetadataAcknowledge nack = new WriteMetadataAcknowledge(
                        filename, false, mySelf, writeM.getRequestID()
                );
                sendMessage(channelID, nack, APP_CLIENT_WRITER, host, 0);
                return;
            }


            // 2. Substituir ficheiro metadata (sobrescreve)
            Path metadataFile = fileDir.resolve("metadata");
            Files.write(metadataFile, metadataBytes);

            System.out.println("Substituído metadata (size: " + metadataBytes.length + " bytes)");
            System.out.println("Content preview: "
                    + new String(metadataBytes, StandardCharsets.UTF_8).substring(0, 50) + "...");

            // 3. Responder ACK
            WriteMetadataAcknowledge ack = new WriteMetadataAcknowledge(
                    filename, true, mySelf, writeM.getRequestID()
            );
            sendMessage(channelID, ack, APP_CLIENT_WRITER, host, 0);

        } catch (IOException e) {
            System.err.println("Erro ao processar WriteMetadata: " + e.getMessage());

            WriteMetadataAcknowledge nack = new WriteMetadataAcknowledge(
                    writeM.getFilename(), false, mySelf, writeM.getRequestID()
            );
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
        System.out.println("[STORAGE] Received ReadMetadata for file: " + readM.getFilename());
        try {

            if(!readM.checkSignature(publicKeys.get(host))){
                logger.error("[STORAGE] ERROR CHECKING PUBLIC KEY");
                return;
            }

            String filename = readM.getFilename();
            Path fileDir = Paths.get(mySelf.getPort() + "-storage/" + filename);

            if (!Files.exists(fileDir)) {
                System.err.println("[STORAGE] File directory does not exist: " + fileDir);
                return;
            }

            Path metadataFile = fileDir.resolve("metadata");
            if (!Files.exists(metadataFile)) {
                System.err.println("[STORAGE] Metadata file not found for " + filename);
                return;
            }

            byte[] metadataBytes = Files.readAllBytes(metadataFile);
            String[] parts = new String(metadataBytes, StandardCharsets.UTF_8).split("\\|");
            if (parts.length != 4) {
                System.err.println("[STORAGE] Metadata format invalid for " + filename);
                return;
            }

            int version = Integer.parseInt(parts[0]);
            String fileHash = parts[1];
            int shareIndex = Integer.parseInt(parts[2]);
            byte[] keyShare = java.util.Base64.getDecoder().decode(parts[3]);

            Metadata metaMsg = new Metadata(
                    readM.getFilename(),
                    version,
                    fileHash,
                    shareIndex,
                    keyShare,
                    readM.getRequestID()
            );

            sendMessage(channelID, metaMsg, APP_CLIENT_WRITER, host, 0);
            System.out.println("[STORAGE] Sent Metadata for " + filename + " to " + host);

        } catch (IOException e) {
            System.err.println("[STORAGE] Error reading metadata: " + e.getMessage());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private void uponReceiveReadMessage(Read read, Host host, short sourceProto, int channelID) {
        System.out.println("[STORAGE] Received Read (data request) for file: " + read.getFilename());
        try {

            if(!read.checkSignature(publicKeys.get(host))){
                logger.error("[STORAGE] ERROR CHECKING PUBLIC KEY");
                return;
            }

            String filename = read.getFilename();
            int requestedVersion = read.getVersion();
            Path valueFile = Paths.get(mySelf.getPort() + "-storage/" + filename, "value-" + requestedVersion);

            if (!Files.exists(valueFile)) {
                System.err.println("[STORAGE] Value file does not exist: " + valueFile);
                return;
            }

            byte[] encryptedFile = Files.readAllBytes(valueFile);
            ReadData dataMsg = new ReadData(filename, requestedVersion, encryptedFile, read.getRequestID());
            sendMessage(channelID, dataMsg, APP_CLIENT_WRITER, host, 0);
            
            System.out.println("[STORAGE] Sent ReadData for " + filename + " to " + host);
        } catch (IOException e) {
            System.err.println("[STORAGE] Error reading file: " + e.getMessage());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}
