package messages;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
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
    private final String identifier;
    private final byte[] signature;
    private final boolean success;
    private final String message;

    public Metadata(String filename, int version, String fileHash,
            int shareIndex, byte[] keyShare, UUID requestID,
            String identifier, byte[] signature, boolean success, String message) {
        super(MESSAGE_ID);
        this.filename = filename;
        this.version = version;
        this.fileHash = fileHash;
        this.shareIndex = shareIndex;
        this.keyShare = keyShare;
        this.requestID = requestID;
        this.identifier = identifier;
        this.signature = signature;
        this.success = success;
        this.message = message;
    }

    public String getIdentifier() {
        return identifier;
    }

    public byte[] getSignature() {
        return signature;
    }

    public String getFilename() {
        return filename;
    }

    public int getVersion() {
        return version;
    }

    public String getFileHash() {
        return fileHash;
    }

    public int getShareIndex() {
        return shareIndex;
    }

    public byte[] getKeyShare() {
        return keyShare;
    }

    public UUID getRequestID() {
        return requestID;
    }

    public boolean getSuccess() {
        return success;
    }

    public String getMessage() {
        return message;
    }

    public static final SignedMessageSerializer<Metadata> serializer = new SignedMessageSerializer<Metadata>() {

        @Override
        public void serializeBody(Metadata msg, ByteBuf out) throws IOException {
            // filename
            byte[] f = msg.filename.getBytes(StandardCharsets.UTF_8);
            out.writeInt(f.length);
            out.writeBytes(f);

            out.writeInt(msg.version);

            byte[] hash = msg.fileHash.getBytes(StandardCharsets.UTF_8);
            out.writeInt(hash.length);
            out.writeBytes(hash);

            out.writeInt(msg.shareIndex);

            out.writeInt(msg.keyShare.length);
            out.writeBytes(msg.keyShare);

            long msb = msg.requestID.getMostSignificantBits();
            long lsb = msg.requestID.getLeastSignificantBits();
            out.writeLong(msb);
            out.writeLong(lsb);

            byte[] id = msg.identifier.getBytes(StandardCharsets.UTF_8);
            out.writeInt(id.length);
            out.writeBytes(id);

            out.writeInt(msg.signature.length);
            out.writeBytes(msg.signature);

            out.writeBoolean(msg.success);

            // Message
            byte[] msgBytes = msg.message.getBytes();
            out.writeInt(msgBytes.length);
            out.writeBytes(msgBytes);
        }

        @Override
        public Metadata deserializeBody(ByteBuf in) throws IOException {
            int len = in.readInt();
            byte[] buff = new byte[len];
            in.readBytes(buff);
            String filename = new String(buff, StandardCharsets.UTF_8);

            int version = in.readInt();

            len = in.readInt();
            byte[] hashBytes = new byte[len];
            in.readBytes(hashBytes);
            String fileHash = new String(hashBytes, StandardCharsets.UTF_8);

            int shareIndex = in.readInt();

            len = in.readInt();
            byte[] keyShare = new byte[len];
            in.readBytes(keyShare);

            long msb = in.readLong();
            long lsb = in.readLong();
            UUID req = new UUID(msb, lsb);

            len = in.readInt();
            byte[] idBytes = new byte[len];
            in.readBytes(idBytes);
            String identifier = new String(idBytes, StandardCharsets.UTF_8);

            len = in.readInt();
            byte[] signature = new byte[len];
            in.readBytes(signature);

            boolean success = in.readBoolean();

            // Message
            len = in.readInt();
            byte[] msgBytes = new byte[len];
            in.readBytes(msgBytes);
            String message = new String(msgBytes);

            return new Metadata(filename, version, fileHash, shareIndex, keyShare,
                    req, identifier, signature, success, message);
        }

    };

    @Override
    public SignedMessageSerializer<? extends SignedProtoMessage> getSerializer() {
        return serializer;
    }
}
