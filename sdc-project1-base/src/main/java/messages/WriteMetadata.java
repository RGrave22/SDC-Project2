package messages;

import io.netty.buffer.ByteBuf;
import pt.unl.fct.di.novasys.babel.generic.signed.SignedMessageSerializer;
import pt.unl.fct.di.novasys.babel.generic.signed.SignedProtoMessage;

import java.io.IOException;

public class WriteMetadata extends SignedProtoMessage {
    public final static short MESSAGE_ID = 703;

    private final String filename;

    private final int version;

    private final byte[] keyShare;

    private final byte[] digest;

    public WriteMetadata(String filename, int version,byte[] keyShare, byte[] digest) {
        super(MESSAGE_ID);
        this.filename = filename;
        this.version = version;
        this.keyShare = keyShare;
        this.digest = digest;
    }

    public String getFilename() {
        return filename;
    }

    public int getVersion() {
        return version;
    }

    public byte[] getKeyShare() {
        return keyShare;
    }

    public byte[] getDigest() {
        return digest;
    }

    public static final SignedMessageSerializer<WriteMetadata> serializer = new SignedMessageSerializer<WriteMetadata>() {

        @Override
        public void serializeBody(WriteMetadata msg, ByteBuf out) throws IOException {

            // Filename
            out.writeInt(msg.filename.length());
            out.writeBytes(msg.filename.getBytes());

            // Versions
            out.writeInt(msg.version);

            // keyShare
            out.writeInt(msg.keyShare.length);
            out.writeBytes(msg.keyShare);

            // keyShare
            out.writeInt(msg.digest.length);
            out.writeBytes(msg.digest);


        }

        @Override
        public WriteMetadata deserializeBody(ByteBuf in) throws IOException {

            // Filename
            int len = in.readInt();
            byte[] buffer = new byte[len];
            in.readBytes(buffer);
            String filename = new String(buffer);

            // Client ID
            int version = in.readInt();

            // keyShare
            len = in.readInt();
            byte[] keyShare = new byte[len];
            in.readBytes(keyShare);

            // Digest
            len = in.readInt();
            byte[] digest = new byte[len];
            in.readBytes(digest);

            return new WriteMetadata(filename, version, keyShare, digest);
        }
    };

    @Override
    public SignedMessageSerializer<? extends SignedProtoMessage> getSerializer() {
        return WriteMetadata.serializer;
    }
}
