package messages;

import io.netty.buffer.ByteBuf;
import pt.unl.fct.di.novasys.babel.generic.signed.SignedMessageSerializer;
import pt.unl.fct.di.novasys.babel.generic.signed.SignedProtoMessage;

import java.io.IOException;
import java.util.UUID;

/**
 * Write Data Unit:
 * - Symmetric key is generated to encrypt file and then send the encrypted data to all clouds.
 * The key is then splited into n pieces (n=number of clouds) and a piece is sent to each clouds
 */
public class Write extends SignedProtoMessage {

    public final static short MESSAGE_ID = 701;

    private final String clientID;
    private final byte[] encryptedFile;
    private final String filename;
    private final int version;
    private final UUID requestID;

    /**
     * Construtor principal
     */
    public Write(String clientID, byte[] encryptedFile, String filename, int version) {
        super(MESSAGE_ID);
        this.clientID = clientID;
        this.requestID = UUID.randomUUID();
        this.encryptedFile = encryptedFile;
        this.filename = filename;
        this.version = version;
    }

    /**
     * Construtor com requestID específico (desserialização)
     */
    public Write(String clientID, byte[] encryptedFile, String filename, int version, UUID requestID) {
        super(MESSAGE_ID);
        this.clientID = clientID;
        this.requestID = requestID;
        this.encryptedFile = encryptedFile;
        this.filename = filename;
        this.version = version;
    }

    // Getters
    public byte[] getEncryptedFile() {
        return encryptedFile;
    }

    public String getFilename() {
        return filename;
    }

    public String getClientID() {
        return clientID;
    }

    public UUID getRequestID() {
        return requestID;
    }

    public int getVersion() {
        return version;
    }

    public static final SignedMessageSerializer<Write> serializer = new SignedMessageSerializer<Write>() {

        @Override
        public void serializeBody(Write msg, ByteBuf out) throws IOException {
            // Client ID
            out.writeInt(msg.clientID.length());
            out.writeBytes(msg.clientID.getBytes());

            // Request ID
            out.writeLong(msg.requestID.getMostSignificantBits());
            out.writeLong(msg.requestID.getLeastSignificantBits());

            // Filename
            out.writeInt(msg.filename.length());
            out.writeBytes(msg.filename.getBytes());

            // Version
            out.writeInt(msg.version);

            // Encrypted File
            out.writeInt(msg.encryptedFile.length);
            out.writeBytes(msg.encryptedFile);
        }

        @Override
        public Write deserializeBody(ByteBuf in) throws IOException {
            // Client ID
            int len = in.readInt();
            byte[] buffer = new byte[len];
            in.readBytes(buffer);
            String clientID = new String(buffer);

            // Request ID
            UUID requestID = new UUID(in.readLong(), in.readLong());

            // Filename
            len = in.readInt();
            buffer = new byte[len];
            in.readBytes(buffer);
            String filename = new String(buffer);

            // Version
            int version = in.readInt();

            // Encrypted File
            len = in.readInt();
            byte[] encryptedFile = new byte[len];
            in.readBytes(encryptedFile);

            return new Write(clientID, encryptedFile, filename, version, requestID);
        }
    };

    @Override
    public SignedMessageSerializer<? extends SignedProtoMessage> getSerializer() {
        return Write.serializer;
    }

    @Override
    public String toString() {
        return String.format("Write{client=%s, filename=%s, v=%d, req=%s, size=%d}",
                clientID, filename, version, requestID, encryptedFile.length);
    }
}
