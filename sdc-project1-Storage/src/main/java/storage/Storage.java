package storage;

import broadcast.messages.BroadcastMessage;
import broadcast.notifications.DeliveryNotification;
import broadcast.requests.BroadcastRequest;
import common.events.ChannelAvailable;
import common.events.NeighborDown;
import common.events.NeighborUp;
import membership.staticmembership.message.HelloMessage;
import membership.staticmembership.message.HelloReplyMessage;
import membership.staticmembership.message.ReplyMessage;
import messages.Write;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import pt.unl.fct.di.novasys.babel.core.GenericProtocol;
import pt.unl.fct.di.novasys.babel.exceptions.HandlerRegistrationException;
import pt.unl.fct.di.novasys.babel.generic.ProtoMessage;
import pt.unl.fct.di.novasys.channel.simpleclientserver.SimpleServerChannel;
import pt.unl.fct.di.novasys.channel.tcp.TCPChannel;
import pt.unl.fct.di.novasys.network.data.Host;
import utils.Crypto;

import java.io.IOException;
import java.net.InetAddress;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Properties;
import java.util.UUID;

public class Storage extends GenericProtocol {

	public static final String PROTO_NAME = "BestEffortBroadcast";
	public static final short PROTO_ID = 300;

    public static final String ADDRESS_KEY = "address";
    public static final String SERVER_PORT_KEY = "server_port";

    public final static String PAR_MYHOST = "membership.myhost";

    private HashSet<UUID> delivered;
	private HashSet<Host> neighbors;
	private HashMap<Host, PublicKey> publicKeys;
	
	private Host mySelf;
	private PublicKey myPublicKey;
	private PrivateKey myPrivateKey;
	
	private int channelID;
	
	private final Logger logger = LogManager.getLogger(Storage.class);
	
	public Storage() {
		super(PROTO_NAME, PROTO_ID);
		
		delivered = new HashSet<UUID>();
		neighbors = new HashSet<Host>();
		publicKeys = new HashMap<Host, PublicKey>();
		
		this.mySelf = null;
		this.myPublicKey = null;
		this.myPrivateKey = null;
	}

	@Override
	public void init(Properties props) throws HandlerRegistrationException, IOException {
        String[] hostElements = props.getProperty(PAR_MYHOST).split(":");

        this.mySelf = new Host(InetAddress.getByName(hostElements[0]), Short.parseShort(hostElements[1]));

        Properties channelProps = new Properties();
        channelProps.put(SimpleServerChannel.ADDRESS_KEY, props.getProperty(ADDRESS_KEY));
        channelProps.put(SimpleServerChannel.PORT_KEY, props.getProperty(SERVER_PORT_KEY));

        channelID = createChannel(SimpleServerChannel.NAME, channelProps);



        registerMessageSerializer(channelID, Write.MESSAGE_ID, Write.serializer);
//        registerMessageSerializer(channelID, HelloReplyMessage.MESSAGE_ID, HelloReplyMessage.serializer);
//        registerMessageSerializer(channelID, ReplyMessage.MESSAGE_ID, ReplyMessage.serializer);


        registerMessageHandler(channelID, Write.MESSAGE_ID, this::uponReceiveWriteMessage);
//        registerMessageHandler(channelID, HelloReplyMessage.MESSAGE_ID, this::uponReceiveHelloReplyMessage);
//        registerMessageHandler(channelID, ReplyMessage.MESSAGE_ID, this::uponReceiveReplyMessage);



	}

    private void uponReceiveWriteMessage(ProtoMessage protoMessage, Host host, short i, int i1) {
        System.out.println("RECEBI O WRITE");
    }


}
