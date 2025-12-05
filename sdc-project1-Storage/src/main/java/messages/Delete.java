package messages;

import java.io.IOException;
import java.util.UUID;

import io.netty.buffer.ByteBuf;
import pt.unl.fct.di.novasys.babel.generic.signed.SignedMessageSerializer;
import pt.unl.fct.di.novasys.babel.generic.signed.SignedProtoMessage;

public class Delete extends SignedProtoMessage {

    public static final short MESSAGE_ID = 108;

    private final String filename;
    private final UUID requestID;

    public Delete(String filename) {
        super(MESSAGE_ID);
        this.filename = filename;
        this.requestID = UUID.randomUUID();
    }

    public Delete(String filename, UUID requestID) {
        super(MESSAGE_ID);
        this.filename = filename;
        this.requestID = requestID;
    }

    public String getFilename() {
        return filename;
    }

    public UUID getRequestID() {
        return requestID;
    }

    public static final SignedMessageSerializer<Delete> serializer
            = new SignedMessageSerializer<Delete>() {

        @Override
        public void serializeBody(Delete msg, ByteBuf out) throws IOException {
            byte[] filenameBytes = msg.filename.getBytes();
            out.writeInt(filenameBytes.length);
            out.writeBytes(filenameBytes);

            out.writeLong(msg.requestID.getMostSignificantBits());
            out.writeLong(msg.requestID.getLeastSignificantBits());
        }

        @Override
        public Delete deserializeBody(ByteBuf in) throws IOException {
            int len = in.readInt();
            byte[] buff = new byte[len];
            in.readBytes(buff);
            String filename = new String(buff);

            UUID requestID = new UUID(in.readLong(), in.readLong());

            return new Delete(filename, requestID);
        }
    };

    @Override
    public SignedMessageSerializer<? extends SignedProtoMessage> getSerializer() {
        return serializer;
    }
}
