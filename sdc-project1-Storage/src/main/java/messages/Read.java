package messages;

import java.io.IOException;
import java.util.UUID;

import io.netty.buffer.ByteBuf;
import pt.unl.fct.di.novasys.babel.generic.signed.SignedMessageSerializer;
import pt.unl.fct.di.novasys.babel.generic.signed.SignedProtoMessage;

public class Read extends SignedProtoMessage {

    public static final short MESSAGE_ID = 711;

    private final String filename;
    private final UUID requestID;
    private final int version;

    public Read(String filename, int version, UUID requestID) {
        super(MESSAGE_ID);
        this.filename = filename;
        this.version = version;
        this.requestID = requestID;
    }

    public String getFilename() {
        return filename;
    }

    public UUID getRequestID() {
        return requestID;
    }

    public int getVersion() {
        return version;
    }

    public static final SignedMessageSerializer<Read> serializer
            = new SignedMessageSerializer<Read>() {

        @Override
        public void serializeBody(Read msg, ByteBuf out) throws IOException {
            byte[] f = msg.filename.getBytes();
            out.writeInt(f.length);
            out.writeBytes(f);

            out.writeInt(msg.version);

            out.writeLong(msg.requestID.getMostSignificantBits());
            out.writeLong(msg.requestID.getLeastSignificantBits());
        }

        @Override
        public Read deserializeBody(ByteBuf in) throws IOException {

            int len = in.readInt();
            byte[] buff = new byte[len];
            in.readBytes(buff);
            String filename = new String(buff);

            int version = in.readInt();

            long msb = in.readLong();
            long lsb = in.readLong();
            UUID req = new UUID(msb, lsb);

            return new Read(filename, version, req);
        }
    };

    @Override
    public SignedMessageSerializer<? extends SignedProtoMessage> getSerializer() {
        return serializer;
    }
}
