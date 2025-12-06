package messages;

import java.io.IOException;
import java.net.InetAddress;
import java.util.UUID;

import io.netty.buffer.ByteBuf;
import pt.unl.fct.di.novasys.babel.generic.signed.SignedMessageSerializer;
import pt.unl.fct.di.novasys.babel.generic.signed.SignedProtoMessage;
import pt.unl.fct.di.novasys.network.data.Host;

public class WriteMetadataAcknowledge extends SignedProtoMessage {

    public final static short MESSAGE_ID = 704;

    private final String filename;

    private final boolean success;

    private final Host server;

    private final UUID requestID;

    private final String message;

    public WriteMetadataAcknowledge(String filename, boolean success, Host server, String message) {
        super(MESSAGE_ID);
        this.filename = filename;
        this.success = success;
        this.server = server;
        this.requestID = UUID.randomUUID();
        this.message = message;
    }

    public WriteMetadataAcknowledge(String filename, boolean success, Host server, UUID requestID, String message) {
        super(MESSAGE_ID);
        this.filename = filename;
        this.success = success;
        this.server = server;
        this.requestID = requestID;
        this.message = message;
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

    public String getMessage() {
        return message;
    }

    public static final SignedMessageSerializer<WriteMetadataAcknowledge> serializer
            = new SignedMessageSerializer<WriteMetadataAcknowledge>() {

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

            // Message
            byte[] msgBytes = msg.message.getBytes();
            out.writeInt(msgBytes.length);
            out.writeBytes(msgBytes);
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

            // Message
            len = in.readInt();
            byte[] msgBytes = new byte[len];
            in.readBytes(msgBytes);
            String message = new String(msgBytes);

            return new WriteMetadataAcknowledge(filename, success, server, rID, message);
        }
    };

    @Override
    public SignedMessageSerializer<? extends SignedProtoMessage> getSerializer() {
        return WriteMetadataAcknowledge.serializer;
    }
}
