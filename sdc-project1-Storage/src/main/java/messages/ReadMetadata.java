package messages;

import java.io.IOException;
import java.util.UUID;

import io.netty.buffer.ByteBuf;
import pt.unl.fct.di.novasys.babel.generic.signed.SignedMessageSerializer;
import pt.unl.fct.di.novasys.babel.generic.signed.SignedProtoMessage;

public class ReadMetadata extends SignedProtoMessage {

    public static final short MESSAGE_ID = 713;

    private final String filename;
    private final UUID requestID;

    public ReadMetadata(String filename, UUID requestID) {
        super(MESSAGE_ID);
        this.filename = filename;
        this.requestID = requestID;
    }

    public String getFilename() { return filename; }
    public UUID getRequestID() { return requestID; }

    public static final SignedMessageSerializer<ReadMetadata> serializer =
            new SignedMessageSerializer<ReadMetadata>() {

                @Override
                public void serializeBody(ReadMetadata msg, ByteBuf out) throws IOException {

                    byte[] f = msg.filename.getBytes();
                    out.writeInt(f.length);
                    out.writeBytes(f);

                    out.writeLong(msg.requestID.getMostSignificantBits());
                    out.writeLong(msg.requestID.getLeastSignificantBits());
                }

                @Override
                public ReadMetadata deserializeBody(ByteBuf in) throws IOException {

                    int len = in.readInt();
                    byte[] buff = new byte[len];
                    in.readBytes(buff);
                    String filename = new String(buff);

                    long msb = in.readLong();
                    long lsb = in.readLong();
                    UUID req = new UUID(msb, lsb);

                    return new ReadMetadata(filename, req);
                }
            };

    @Override
    public SignedMessageSerializer<? extends SignedProtoMessage> getSerializer() {
        return serializer;
    }
}
