package messages;

import java.io.IOException;
import java.util.UUID;

import io.netty.buffer.ByteBuf;
import pt.unl.fct.di.novasys.babel.generic.signed.SignedMessageSerializer;
import pt.unl.fct.di.novasys.babel.generic.signed.SignedProtoMessage;

public class ReadData extends SignedProtoMessage {

    public static final short MESSAGE_ID = 714;

    private final String filename;
    private final int version;
    private final byte[] encryptedFile;
    private final UUID requestID;

    public ReadData(String filename, int version, byte[] encryptedFile, UUID requestID) {
        super(MESSAGE_ID);
        this.filename = filename;
        this.version = version;
        this.encryptedFile = encryptedFile;
        this.requestID = requestID;
    }

    public String getFilename() { return filename; }
    public int getVersion() { return version; }
    public byte[] getEncryptedFile() { return encryptedFile; }
    public UUID getRequestID() { return requestID; }

    public static final SignedMessageSerializer<ReadData> serializer =
            new SignedMessageSerializer<ReadData>() {

                @Override
                public void serializeBody(ReadData msg, ByteBuf out) throws IOException {

                    byte[] f = msg.filename.getBytes();
                    out.writeInt(f.length);
                    out.writeBytes(f);

                    out.writeInt(msg.version);

                    out.writeInt(msg.encryptedFile.length);
                    out.writeBytes(msg.encryptedFile);

                    out.writeLong(msg.requestID.getMostSignificantBits());
                    out.writeLong(msg.requestID.getLeastSignificantBits());
                }

                @Override
                public ReadData deserializeBody(ByteBuf in) throws IOException {

                    int len = in.readInt();
                    byte[] fbuff = new byte[len];
                    in.readBytes(fbuff);
                    String filename = new String(fbuff);

                    int version = in.readInt();

                    len = in.readInt();
                    byte[] enc = new byte[len];
                    in.readBytes(enc);

                    long msb = in.readLong();
                    long lsb = in.readLong();
                    UUID req = new UUID(msb, lsb);

                    return new ReadData(filename, version, enc, req);
                }
            };

    @Override
    public SignedMessageSerializer<? extends SignedProtoMessage> getSerializer() {
        return serializer;
    }
}
