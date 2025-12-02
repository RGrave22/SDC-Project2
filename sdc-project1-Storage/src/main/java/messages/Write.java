package messages;

import java.io.IOException;
import java.util.UUID;

import io.netty.buffer.ByteBuf;
import pt.unl.fct.di.novasys.babel.generic.signed.SignedMessageSerializer;
import pt.unl.fct.di.novasys.babel.generic.signed.SignedProtoMessage;

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

    private final UUID requestID;


    public Write(String clientID, byte[] encryptedFile, String filename) {
        super(MESSAGE_ID);
        this.clientID = clientID;
        this.requestID = UUID.randomUUID();
        this.encryptedFile = encryptedFile;
        this.filename = filename;
    }

    public Write(String clientID, byte[] encryptedFile, String filename, UUID requestID) {
        super(MESSAGE_ID);
        this.clientID = clientID;
        this.requestID = requestID;
        this.encryptedFile = encryptedFile;
        this.filename = filename;
    }


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

    public static final SignedMessageSerializer<Write> serializer = new SignedMessageSerializer<Write>() {

        @Override
        public void serializeBody(Write msg, ByteBuf out) throws IOException {

            // Client ID
            out.writeInt(msg.clientID.length());
            out.writeBytes(msg.clientID.getBytes());

            // ReqId
            out.writeLong(msg.requestID.getMostSignificantBits());
            out.writeLong(msg.requestID.getLeastSignificantBits());

            // Filename
            out.writeInt(msg.filename.length());
            out.writeBytes(msg.filename.getBytes());

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

            // ReqId
            UUID rID = new UUID(in.readLong(), in.readLong());

            // Filename
            len = in.readInt();
            buffer = new byte[len];
            in.readBytes(buffer);
            String filename = new String(buffer);

            // Encrypted File
            len = in.readInt();
            byte[] encryptedFile = new byte[len];
            in.readBytes(encryptedFile);

            return new Write(clientID, encryptedFile, filename, rID);
        }
    };

    @Override
    public SignedMessageSerializer<? extends SignedProtoMessage> getSerializer() {
        return Write.serializer;
    }
}
