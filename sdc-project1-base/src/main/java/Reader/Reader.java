package Reader;

import broadcast.messages.BroadcastMessage;
import broadcast.notifications.DeliveryNotification;
import broadcast.requests.BroadcastRequest;
import common.events.ChannelAvailable;
import common.events.NeighborDown;
import common.events.NeighborUp;
import messages.Write;
import messages.WriteAcknowledge;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.codahale.shamir.Scheme;

import pt.unl.fct.di.novasys.babel.core.GenericProtocol;
import pt.unl.fct.di.novasys.babel.exceptions.HandlerRegistrationException;
import pt.unl.fct.di.novasys.babel.generic.ProtoMessage;
import pt.unl.fct.di.novasys.channel.simpleclientserver.SimpleClientChannel;
import pt.unl.fct.di.novasys.channel.tcp.TCPChannel;
import pt.unl.fct.di.novasys.network.data.Host;
import utils.Crypto;

import java.io.IOException;
import java.net.InetAddress;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.UUID;

public class Reader extends GenericProtocol {

    public static final String PROTO_NAME = "BestEffortBroadcast";
    public static final short PROTO_ID = 1100;

    public final static short APP_SERVER_PROTO = 300;

    private HashSet<UUID> delivered;
    private HashSet<Host> neighbors;
    private HashMap<Host, PublicKey> publicKeys;

    private Host mySelf;
    private PublicKey myPublicKey;
    private PrivateKey myPrivateKey;

    private KeyStore truststore;
    private String writer = "node1";
    private PublicKey writerPublicKey;
    public final static String PAR_MYHOST = "membership.myhost";
    public final static String STORAGE = "storage.services";

    private int channelID;
    private int[] hostChannels;

    //Shamir
    private Scheme scheme;
    private int threshold;
    private List<Host> servers;

    private final Logger logger = LogManager.getLogger(Reader.class);

    public Reader() {
        super(PROTO_NAME, PROTO_ID);

        delivered = new HashSet<UUID>();
        neighbors = new HashSet<Host>();
        publicKeys = new HashMap<Host, PublicKey>();

        this.mySelf = null;
        this.myPublicKey = null;
        this.myPrivateKey = null;
        this.truststore = null;
        this.writerPublicKey = null;

        this.servers = new ArrayList<>();
    }

    @Override
    public void init(Properties props) throws HandlerRegistrationException, IOException {

        try {
            this.truststore = Crypto.getTruststore(props);

            String myIdentifier = props.getProperty(Crypto.CRYPTO_NAME_KEY);

            writerPublicKey = (PublicKey) truststore.getCertificate(writer).getPublicKey();

            if (writerPublicKey == null) {
                logger.error("[READER] Writer public key is NULL for id: " + writer);
                System.out.println("[READER] ERRO: writerPublicKey é NULL para '" + writer + "'");
            } else {
                //PARA VERIFICAR SE A KEY ESTA CERTA
                java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
                byte[] hash = digest.digest(writerPublicKey.getEncoded());
                StringBuilder hex = new StringBuilder();
                for (byte b : hash) {
                    hex.append(String.format("%02x", b));
                }
                logger.info("[READER] Writer public key fingerprint (SHA-256): " + hex);
                System.out.println("[READER] Writer public key fingerprint (SHA-256): " + hex);
            }

        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }

        String[] hostElements = props.getProperty(PAR_MYHOST).split(":");
        this.mySelf = new Host(InetAddress.getByName(hostElements[0]), Short.parseShort(hostElements[1]));

        String[] storageList = props.getProperty(STORAGE).split(",");
        for (String s : storageList) {
            String[] e = s.split(":");
            Host candidate = new Host(InetAddress.getByName(e[0]), Short.parseShort(e[1]));
            // System.out.println("Candidate: " + candidate.toString());
            // System.out.println("Address: " + candidate.getAddress());
            // System.out.println("Port: " + candidate.getPort());
            servers.add(candidate);
        }

        int f = (servers.size() - 1) / 3;
        this.threshold = f + 1;
        this.scheme = new Scheme(new SecureRandom(), servers.size(), threshold);

        hostChannels = new int[servers.size()];

        for (int i = 0; i < servers.size(); i++) {

            Properties channelProps = new Properties();
            // System.out.println("Candidate: " + servers.get(i).toString());
            // System.out.println("Address: " + servers.get(i).getAddress());
            // System.out.println("Port: " + servers.get(i).getPort());
            channelProps.put(SimpleClientChannel.ADDRESS_KEY, servers.get(i).getAddress().getHostAddress());
            channelProps.put(SimpleClientChannel.PORT_KEY, String.valueOf(servers.get(i).getPort()));

            hostChannels[i] = createChannel(SimpleClientChannel.NAME, channelProps);

            //Messages
            registerMessageSerializer(hostChannels[i], WriteAcknowledge.MESSAGE_ID, WriteAcknowledge.serializer);
            registerMessageSerializer(hostChannels[i], Write.MESSAGE_ID, Write.serializer);

            registerMessageHandler(hostChannels[i], WriteAcknowledge.MESSAGE_ID, this::uponReceiveWriteAck);

            openConnection(servers.get(i), hostChannels[i]);
            System.out.println("[WRITER] Estamos a abrir um canal entre: " + servers.get(i).toString() + ": " + channelID);

        }

    }

    private void uponReceiveReadAck(ProtoMessage protoMessage, Host host, short i, int i1) {

    }

    private void uponReceiveWriteAck(ProtoMessage protoMessage, Host host, short i, int i1) {
        System.out.println("RECEBI A OUTRA CENA");
    }

}
