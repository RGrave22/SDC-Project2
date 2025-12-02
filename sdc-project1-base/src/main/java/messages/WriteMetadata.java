package messages;

import java.io.IOException;
import java.util.UUID;

import io.netty.buffer.ByteBuf;
import pt.unl.fct.di.novasys.babel.generic.signed.SignedMessageSerializer;
import pt.unl.fct.di.novasys.babel.generic.signed.SignedProtoMessage;

public class WriteMetadata extends SignedProtoMessage {
    public final static short MESSAGE_ID = 703;

    private final String filename;

    private final int version;

    private final byte[] fileBytes;

    private final byte[] digest;

    private UUID requestID;

    public WriteMetadata(String filename, int version,byte[] fileBytes, byte[] digest) {
        super(MESSAGE_ID);
        this.filename = filename;
        this.version = version;
        this.fileBytes = fileBytes;
        this.digest = digest;
        this.requestID = UUID.randomUUID();
    }

    public WriteMetadata(String filename, int version,byte[] fileBytes, byte[] digest, UUID requestID) {
        super(MESSAGE_ID);
        this.filename = filename;
        this.version = version;
        this.fileBytes = fileBytes;
        this.digest = digest;
        this.requestID = requestID;
    }

    public UUID getRequestID() {
        return requestID;
    }

    public String getFilename() {
        return filename;
    }

    public int getVersion() {
        return version;
    }

    public byte[] getFileBytes() {
        return fileBytes;
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

            //ReqId
            out.writeLong(msg.requestID.getMostSignificantBits());
            out.writeLong(msg.requestID.getLeastSignificantBits());

            // Versions
            out.writeInt(msg.version);

            // fileBytes
            out.writeInt(msg.fileBytes.length);
            out.writeBytes(msg.fileBytes);

            // fileBytes
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

            // ReqId
            UUID rID = new UUID(in.readLong(), in.readLong());

            // Client ID
            int version = in.readInt();

            // fileBytes
            len = in.readInt();
            byte[] fileBytes = new byte[len];
            in.readBytes(fileBytes);

            // Digest
            len = in.readInt();
            byte[] digest = new byte[len];
            in.readBytes(digest);

            return new WriteMetadata(filename, version, fileBytes, digest, rID);
        }
    };

    @Override
    public SignedMessageSerializer<? extends SignedProtoMessage> getSerializer() {
        return WriteMetadata.serializer;
    }
}
