package Reader;

import broadcast.messages.BroadcastMessage;
import broadcast.notifications.DeliveryNotification;
import broadcast.requests.BroadcastRequest;
import common.events.ChannelAvailable;
import common.events.NeighborDown;
import common.events.NeighborUp;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import pt.unl.fct.di.novasys.babel.core.GenericProtocol;
import pt.unl.fct.di.novasys.babel.exceptions.HandlerRegistrationException;
import pt.unl.fct.di.novasys.channel.tcp.TCPChannel;
import pt.unl.fct.di.novasys.network.data.Host;
import utils.Crypto;

import java.io.IOException;
import java.net.InetAddress;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Properties;
import java.util.UUID;

public class Reader extends GenericProtocol {

	public static final String PROTO_NAME = "BestEffortBroadcast";
	public static final short PROTO_ID = 1100;
	
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


    private int channelID;
	
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
                for (byte b : hash) hex.append(String.format("%02x", b));
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

        Properties channelProps = new Properties();
        channelProps.put(TCPChannel.ADDRESS_KEY, this.mySelf.getAddress().toString().replace("/", ""));
        channelProps.put(TCPChannel.PORT_KEY, this.mySelf.getPort() + "");

        channelID = createChannel(TCPChannel.NAME, channelProps);



	}
	

}
