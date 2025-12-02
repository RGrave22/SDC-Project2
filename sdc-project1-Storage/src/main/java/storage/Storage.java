package storage;

import java.io.IOException;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.UUID;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import messages.Read;
import messages.ReadAcknowledge;
import messages.ReadMetadata;
import messages.ReadMetadataAcknowledge;
import messages.Write;
import messages.WriteAcknowledge;
import messages.WriteMetadata;
import messages.WriteMetadataAcknowledge;
import pt.unl.fct.di.novasys.babel.core.GenericProtocol;
import pt.unl.fct.di.novasys.babel.exceptions.HandlerRegistrationException;
import pt.unl.fct.di.novasys.babel.generic.ProtoMessage;
import pt.unl.fct.di.novasys.channel.simpleclientserver.SimpleServerChannel;
import pt.unl.fct.di.novasys.network.data.Host;
import utils.Crypto;

import javax.crypto.Cipher;

public class Storage extends GenericProtocol {

    public static final String PROTO_NAME = "BestEffortBroadcast";
    public static final short PROTO_ID = 300;

    public static final short APP_CLIENT_WRITER = 1001;
    public static final short APP_CLIENT_READER = 1100;

    public static final String ADDRESS_KEY = "address";
    public static final String SERVER_PORT_KEY = "server_port";

    public final static String PAR_MYHOST = "membership.myhost";
    public final static String CLIENTS = "client.services";

    private HashSet<UUID> delivered;
    private HashSet<Host> neighbors;
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
        neighbors = new HashSet<Host>();
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

        try {
            this.truststore = Crypto.getTruststore(props);
            this.myPublicKey = this.truststore.getCertificate("node1").getPublicKey();

        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }

        //Messages
        registerMessageSerializer(channelID, Write.MESSAGE_ID, Write.serializer);
        registerMessageSerializer(channelID, Read.MESSAGE_ID, Read.serializer);
        registerMessageSerializer(channelID, WriteAcknowledge.MESSAGE_ID, WriteAcknowledge.serializer);
        registerMessageSerializer(channelID, ReadAcknowledge.MESSAGE_ID, ReadAcknowledge.serializer);
        registerMessageSerializer(channelID, WriteMetadata.MESSAGE_ID, WriteMetadata.serializer);
        //registerMessageSerializer(channelID, ReadAcknowledge.MESSAGE_ID, ReadMetadata.serializer);
        registerMessageSerializer(channelID, WriteMetadataAcknowledge.MESSAGE_ID, WriteMetadataAcknowledge.serializer);
        // registerMessageSerializer(channelID, ReadAcknowledge.MESSAGE_ID, ReadMetadataAcknowledge.serializer);
//        registerMessageSerializer(channelID, HelloReplyMessage.MESSAGE_ID, HelloReplyMessage.serializer);
//        registerMessageSerializer(channelID, ReplyMessage.MESSAGE_ID, ReplyMessage.serializer);

        registerMessageHandler(channelID, Write.MESSAGE_ID, this::uponReceiveWriteMessage);
        registerMessageHandler(channelID, Read.MESSAGE_ID, this::uponReceiveReadMessage);
        registerMessageHandler(channelID, WriteMetadata.MESSAGE_ID, this::uponReceiveWriteMetadata);
//        registerMessageHandler(channelID, HelloReplyMessage.MESSAGE_ID, this::uponReceiveHelloReplyMessage);
//        registerMessageHandler(channelID, ReplyMessage.MESSAGE_ID, this::uponReceiveReplyMessage);

    }

    private void uponReceiveWriteMessage(Write write, Host host, short sourceProto, int channelID) {
        System.out.println("[STORAGE] RECEBI WRITE para " + write.getFilename());

        try {
            String filename = write.getFilename();
            int version = write.getVersion();  // Assumindo que Write tem getVersion()
            byte[] encryptedFile = write.getEncryptedFile();

            // 1. Criar diretório filename (se não existir)
            Path fileDir = Paths.get(mySelf.getPort()+"-storage/" + filename);
            Files.createDirectories(fileDir);
            System.out.println("Criada diretório: " + fileDir);

            // 2. Guardar ficheiro como value-<versão>
            Path valueFile = fileDir.resolve("value-" + version);
            Files.write(valueFile, encryptedFile);

            System.out.println("Guardado value-" + version +
                    " (size: " + encryptedFile.length + " bytes)");

            // 3. Responder ACK
            WriteAcknowledge wAck = new WriteAcknowledge(
                    write.getFilename(),
                    write.getRequestID(),
                    true,
                    this.mySelf
            );
            sendMessage(channelID, wAck, APP_CLIENT_WRITER, host, 0);

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
            throw new RuntimeException(e);
        }
    }

    private void uponReceiveWriteMetadata(WriteMetadata writeM, Host host, short sourceProto, int channelID) {
        System.out.println("[STORAGE] RECEBI WriteMetadata para " + writeM.getFilename());

        try {
            String filename = writeM.getFilename();
            int version = writeM.getVersion();
            byte[] metadataBytes = writeM.getFileBytes();

            // 1. Verificar se diretório existe
            Path fileDir = Paths.get(mySelf.getPort()+"-storage/" + filename);
            if (!Files.exists(fileDir)) {
                System.err.println("Diretório não existe: " + fileDir);
                // NACK se diretório não existir
                WriteMetadataAcknowledge nack = new WriteMetadataAcknowledge(
                        filename, false, mySelf, writeM.getRequestID()
                );
                sendMessage(channelID, nack, APP_CLIENT_WRITER, host, 0);
                return;
            }

            // 2. Substituir ficheiro metadata (sempre sobrescreve)
            Path metadataFile = fileDir.resolve("metadata");
            Files.write(metadataFile, metadataBytes);

            System.out.println("Substituído metadata (size: " + metadataBytes.length + " bytes)");
            System.out.println("Content preview: " +
                    new String(metadataBytes, StandardCharsets.UTF_8).substring(0, 50) + "...");

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
        }
    }


    private void uponReceiveReadMessage(ProtoMessage protoMessage, Host host, short i, int i1) {
        System.out.println("RECEBI O READ");
    }

}
