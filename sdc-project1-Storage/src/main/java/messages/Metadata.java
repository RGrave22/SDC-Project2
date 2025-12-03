package messages;

import java.io.IOException;
import java.net.InetAddress;

import io.netty.buffer.ByteBuf;
import pt.unl.fct.di.novasys.babel.generic.signed.SignedMessageSerializer;
import pt.unl.fct.di.novasys.babel.generic.signed.SignedProtoMessage;
import pt.unl.fct.di.novasys.network.data.Host;

/**
 * Reading a File
 * - This acknowledge comes from only a single host that contains the latest version of the requested file
 * (already confirmed by querying the metadatas)
 *
 * This message brings:
 * - The filename
 * - The encrypted file that is going to be decrypted by the symmetric key already reconstructed by querying the metadatas
 * - a success boolean
 * - the host (cloud) that sent the file
 *
 */
public class Metadata extends SignedProtoMessage {
    public final static short MESSAGE_ID = 712;

    private final String filename;

    private final byte[] encryptedFile;

    private final boolean success;

    private final Host server;

    public Metadata(String filename, byte[] encryptedFile, boolean success, Host server) {
        super(MESSAGE_ID);
        this.filename = filename;
        this.encryptedFile = encryptedFile;
        this.success = success;
        this.server = server;
    }

    public static final SignedMessageSerializer<Metadata> serializer = new SignedMessageSerializer<Metadata>() {

        @Override
        public void serializeBody(Metadata msg, ByteBuf out) throws IOException {

            // Filename
            out.writeInt(msg.filename.length());
            out.writeBytes(msg.filename.getBytes());

            // Encrypted File
            out.writeInt(msg.encryptedFile.length);
            out.writeBytes(msg.encryptedFile);

            // Success
            out.writeBoolean(msg.success);

            // Host (server)
            byte[] addressBytes = msg.server.getAddress().getAddress();
            out.writeInt(addressBytes.length);
            out.writeBytes(addressBytes);

            // Serializa a porta
            out.writeShort(msg.server.getPort());

        }

        @Override
        public Metadata deserializeBody(ByteBuf in) throws IOException {

            // Filename
            int len = in.readInt();
            byte[] buffer = new byte[len];
            in.readBytes(buffer);
            String filename = new String(buffer);

            // Encrypted File
            len = in.readInt();
            byte[] encryptedFile = new byte[len];
            in.readBytes(encryptedFile);

            // Success
            boolean success = in.readBoolean();

            // Host (server)
            len = in.readInt();
            byte[] addressBytes = new byte[len];
            in.readBytes(addressBytes);
            InetAddress address = InetAddress.getByAddress(addressBytes);

            // Desserializa a porta
            short port = in.readShort();

            Host server = new Host(address, port);

            return new Metadata(filename, encryptedFile, success, server);
        }
    };

    @Override
    public SignedMessageSerializer<? extends SignedProtoMessage> getSerializer() {
        return Metadata.serializer;
    }
}
