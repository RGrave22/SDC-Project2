package messages;

import io.netty.buffer.ByteBuf;
import pt.unl.fct.di.novasys.babel.generic.signed.SignedMessageSerializer;
import pt.unl.fct.di.novasys.babel.generic.signed.SignedProtoMessage;
import pt.unl.fct.di.novasys.network.data.Host;

import java.io.IOException;
import java.net.InetAddress;
import java.util.UUID;

public class WriteMetadataAcknowledge extends SignedProtoMessage {
    public final static short MESSAGE_ID = 704;

    private final String filename;

    private final boolean success;

    private final Host server;

    private final UUID requestID;

    public WriteMetadataAcknowledge(String filename,  boolean success, Host server) {
        super(MESSAGE_ID);
        this.filename = filename;
        this.success = success;
        this.server = server;
        this.requestID = UUID.randomUUID();
    }

    public WriteMetadataAcknowledge(String filename,  boolean success, Host server, UUID requestID) {
        super(MESSAGE_ID);
        this.filename = filename;
        this.success = success;
        this.server = server;
        this.requestID = requestID;
    }

    public UUID getRequestID() {
        return requestID;
    }

    public String getFilename() {
        return filename;
    }

    public boolean isSuccess() {
        return success;
    }

    public Host getServer() {
        return server;
    }

    public static final SignedMessageSerializer<WriteMetadataAcknowledge> serializer =
            new SignedMessageSerializer<WriteMetadataAcknowledge>() {

                @Override
                public void serializeBody(WriteMetadataAcknowledge msg, ByteBuf out) throws IOException {
                    // Filename
                    byte[] filenameBytes = msg.filename.getBytes();
                    out.writeInt(filenameBytes.length);
                    out.writeBytes(filenameBytes);

                    //ReqId
                    out.writeLong(msg.requestID.getMostSignificantBits());
                    out.writeLong(msg.requestID.getLeastSignificantBits());

                    // Success
                    out.writeBoolean(msg.success);

                    // Host (server)
                    byte[] addressBytes = msg.server.getAddress().getAddress();
                    out.writeInt(addressBytes.length);
                    out.writeBytes(addressBytes);

                    // Serializa a porta
                    out.writeShort(msg.server.getPort());
                }

                @Override
                public WriteMetadataAcknowledge deserializeBody(ByteBuf in) throws IOException {
                    // Filename
                    int len = in.readInt();
                    byte[] buffer = new byte[len];
                    in.readBytes(buffer);
                    String filename = new String(buffer);

                    // ReqId
                    UUID rID = new UUID(in.readLong(), in.readLong());

                    // Success
                    boolean success = in.readBoolean();

                    // Host (server)
                    len = in.readInt();
                    byte[] addressBytes = new byte[len];
                    in.readBytes(addressBytes);
                    InetAddress address = InetAddress.getByAddress(addressBytes);

                    // Desserializa a porta
                    short port = in.readShort();

                    Host server = new Host(address, port);

                    return new WriteMetadataAcknowledge(filename, success, server, rID);
                }
            };

    @Override
    public SignedMessageSerializer<? extends SignedProtoMessage> getSerializer() {
        return WriteMetadataAcknowledge.serializer;
    }
}
