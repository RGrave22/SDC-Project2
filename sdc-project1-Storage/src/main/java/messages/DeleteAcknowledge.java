package messages;

import java.io.IOException;
import java.util.UUID;

import io.netty.buffer.ByteBuf;
import pt.unl.fct.di.novasys.babel.generic.signed.SignedMessageSerializer;
import pt.unl.fct.di.novasys.babel.generic.signed.SignedProtoMessage;

public class DeleteAcknowledge extends SignedProtoMessage {

    public static final short MESSAGE_ID = 109;

    private final String filename;
    private final UUID requestID;
    private final boolean success;

    public DeleteAcknowledge(String filename, boolean success){
        super(MESSAGE_ID);
        this.filename = filename;
        this.requestID = UUID.randomUUID();
        this.success = success;
    }

    public DeleteAcknowledge(String filename, UUID requestID, boolean success) {
        super(MESSAGE_ID);
        this.filename = filename;
        this.requestID = requestID;
        this.success = success;
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

    public static final SignedMessageSerializer<DeleteAcknowledge> serializer
            = new SignedMessageSerializer<DeleteAcknowledge>() {

        @Override
        public void serializeBody(DeleteAcknowledge msg, ByteBuf out) throws IOException {
            byte[] filenameBytes = msg.filename.getBytes();
            out.writeInt(filenameBytes.length);
            out.writeBytes(filenameBytes);

            out.writeLong(msg.requestID.getMostSignificantBits());
            out.writeLong(msg.requestID.getLeastSignificantBits());

            out.writeBoolean(msg.success);
        }

        @Override
        public DeleteAcknowledge deserializeBody(ByteBuf in) throws IOException {
            int len = in.readInt();
            byte[] buff = new byte[len];
            in.readBytes(buff);
            String filename = new String(buff);

            UUID requestID = new UUID(in.readLong(), in.readLong());

            boolean success = in.readBoolean();

            return new DeleteAcknowledge(filename, requestID, success);
        }
    };

    @Override
    public SignedMessageSerializer<? extends SignedProtoMessage> getSerializer() {
        return serializer;
    }
}
