package storage;

import java.io.IOException;
import java.net.InetAddress;
import java.security.PrivateKey;
import java.security.PublicKey;
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
import messages.Write;
import messages.WriteAcknowledge;
import pt.unl.fct.di.novasys.babel.core.GenericProtocol;
import pt.unl.fct.di.novasys.babel.exceptions.HandlerRegistrationException;
import pt.unl.fct.di.novasys.babel.generic.ProtoMessage;
import pt.unl.fct.di.novasys.channel.simpleclientserver.SimpleServerChannel;
import pt.unl.fct.di.novasys.network.data.Host;

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

        //Messages
        registerMessageSerializer(channelID, Write.MESSAGE_ID, Write.serializer);
        registerMessageSerializer(channelID, Read.MESSAGE_ID, Read.serializer);
        registerMessageSerializer(channelID, WriteAcknowledge.MESSAGE_ID, WriteAcknowledge.serializer);
        registerMessageSerializer(channelID, ReadAcknowledge.MESSAGE_ID, ReadAcknowledge.serializer);
//        registerMessageSerializer(channelID, HelloReplyMessage.MESSAGE_ID, HelloReplyMessage.serializer);
//        registerMessageSerializer(channelID, ReplyMessage.MESSAGE_ID, ReplyMessage.serializer);

        registerMessageHandler(channelID, Write.MESSAGE_ID, this::uponReceiveWriteMessage);
        registerMessageHandler(channelID, Read.MESSAGE_ID, this::uponReceiveReadMessage);
//        registerMessageHandler(channelID, HelloReplyMessage.MESSAGE_ID, this::uponReceiveHelloReplyMessage);
//        registerMessageHandler(channelID, ReplyMessage.MESSAGE_ID, this::uponReceiveReplyMessage);

    }

    private void uponReceiveWriteMessage(Write write, Host host, short sourceProto, int channelID) {
        System.out.println("RECEBI O WRITE");
        WriteAcknowledge wAck = new WriteAcknowledge(write.getFilename(), true, this.mySelf);
        sendMessage(channelID, wAck, APP_CLIENT_READER, host, 0);
    }

    private void uponReceiveReadMessage(ProtoMessage protoMessage, Host host, short i, int i1) {
        System.out.println("RECEBI O READ");
    }

}
