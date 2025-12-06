package messages;

import java.io.IOException;
import java.net.InetAddress;
import java.util.UUID;

import io.netty.buffer.ByteBuf;
import pt.unl.fct.di.novasys.babel.generic.signed.SignedMessageSerializer;
import pt.unl.fct.di.novasys.babel.generic.signed.SignedProtoMessage;
import pt.unl.fct.di.novasys.network.data.Host;

public class WriteAcknowledge extends SignedProtoMessage {

    public final static short MESSAGE_ID = 702;

    private final String filename;

    private final boolean success;

    private final Host server;

    private final UUID requestID;

    private final String message;

    public WriteAcknowledge(String filename, UUID requestID, boolean success, Host server, String message) {
        super(MESSAGE_ID);

        this.filename = filename;
        this.success = success;
        this.server = server;
        this.requestID = requestID;
        this.message = message;
    }

    public String getFilename() {
        return filename;
    }

    public UUID getRequestID() {
        return requestID;
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

    public static final SignedMessageSerializer<WriteAcknowledge> serializer
            = new SignedMessageSerializer<WriteAcknowledge>() {

        @Override
        public void serializeBody(WriteAcknowledge msg, ByteBuf out) throws IOException {
            // Filename
            byte[] filenameBytes = msg.filename.getBytes();
            out.writeInt(filenameBytes.length);
            out.writeBytes(filenameBytes);

            // ReqId
            out.writeLong(msg.requestID.getMostSignificantBits());
            out.writeLong(msg.requestID.getLeastSignificantBits());

            // Success
            out.writeBoolean(msg.success);

            // Host (server)
            byte[] addressBytes = msg.server.getAddress().getAddress();
            out.writeInt(addressBytes.length);
            out.writeBytes(addressBytes);

            // Porta
            out.writeShort(msg.server.getPort());

            // Message
            byte[] msgBytes = msg.message.getBytes();
            out.writeInt(msgBytes.length);
            out.writeBytes(msgBytes);
        }

        @Override
        public WriteAcknowledge deserializeBody(ByteBuf in) throws IOException {
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

            short port = in.readShort();
            Host server = new Host(address, port);

            // Message
            len = in.readInt();
            byte[] msgBytes = new byte[len];
            in.readBytes(msgBytes);
            String message = new String(msgBytes);

            return new WriteAcknowledge(filename, rID, success, server, message);
        }
    };

    @Override
    public SignedMessageSerializer<? extends SignedProtoMessage> getSerializer() {
        return WriteAcknowledge.serializer;
    }

}
