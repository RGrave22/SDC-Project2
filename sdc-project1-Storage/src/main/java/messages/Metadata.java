package messages;

import java.io.IOException;
import java.util.UUID;

import io.netty.buffer.ByteBuf;
import pt.unl.fct.di.novasys.babel.generic.signed.SignedMessageSerializer;
import pt.unl.fct.di.novasys.babel.generic.signed.SignedProtoMessage;

public class Metadata extends SignedProtoMessage {

    public static final short MESSAGE_ID = 712;

    private final String filename;
    private final int version;
    private final String fileHash;
    private final int shareIndex;
    private final byte[] keyShare;
    private final UUID requestID;

    public Metadata(String filename, int version, String fileHash,
                    int shareIndex, byte[] keyShare, UUID requestID) {
        super(MESSAGE_ID);
        this.filename = filename;
        this.version = version;
        this.fileHash = fileHash;
        this.shareIndex = shareIndex;
        this.keyShare = keyShare;
        this.requestID = requestID;
    }

    public String getFilename() { return filename; }
    public int getVersion() { return version; }
    public String getFileHash() { return fileHash; }
    public int getShareIndex() { return shareIndex; }
    public byte[] getKeyShare() { return keyShare; }
    public UUID getRequestID() { return requestID; }

    public static final SignedMessageSerializer<Metadata> serializer =
            new SignedMessageSerializer<Metadata>() {

                @Override
                public void serializeBody(Metadata msg, ByteBuf out) throws IOException {
                    // filename
                    byte[] f = msg.filename.getBytes();
                    out.writeInt(f.length);
                    out.writeBytes(f);

                    out.writeInt(msg.version);

                    byte[] hash = msg.fileHash.getBytes();
                    out.writeInt(hash.length);
                    out.writeBytes(hash);

                    out.writeInt(msg.shareIndex);

                    out.writeInt(msg.keyShare.length);
                    out.writeBytes(msg.keyShare);

                    out.writeLong(msg.requestID.getMostSignificantBits());
                    out.writeLong(msg.requestID.getLeastSignificantBits());
                }

                @Override
                public Metadata deserializeBody(ByteBuf in) throws IOException {

                    int len = in.readInt();
                    byte[] buff = new byte[len];
                    in.readBytes(buff);
                    String filename = new String(buff);

                    int version = in.readInt();

                    len = in.readInt();
                    byte[] hash = new byte[len];
                    in.readBytes(hash);
                    String fileHash = new String(hash);

                    int shareIndex = in.readInt();

                    len = in.readInt();
                    byte[] keyShare = new byte[len];
                    in.readBytes(keyShare);

                    long msb = in.readLong();
                    long lsb = in.readLong();
                    UUID req = new UUID(msb, lsb);

                    return new Metadata(filename, version, fileHash, shareIndex, keyShare, req);
                }
            };

    @Override
    public SignedMessageSerializer<? extends SignedProtoMessage> getSerializer() {
        return serializer;
    }
}
