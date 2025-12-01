package app.messages.depsky.messages;

import io.netty.buffer.ByteBuf;
import pt.unl.fct.di.novasys.babel.generic.signed.SignedMessageSerializer;
import pt.unl.fct.di.novasys.babel.generic.signed.SignedProtoMessage;
import pt.unl.fct.di.novasys.network.data.Host;

import java.io.IOException;
import java.net.InetAddress;

public class WriteAcknowledge extends SignedProtoMessage {
    public final static short MESSAGE_ID = 702;

    private final String filename;

    private final boolean success;

    private final Host server;

    public WriteAcknowledge(String filename,  boolean success,  Host server) {
        super(MESSAGE_ID);

        this.filename = filename;
        this.success = success;
        this.server = server;
    }

    public String getFilename() {
        return filename;
    }

    public boolean isSuccess() {
        return success;
    }

    public Host getServer() {
        return server;
    }


    public static final SignedMessageSerializer<WriteAcknowledge> serializer =
            new SignedMessageSerializer<WriteAcknowledge>() {

                @Override
                public void serializeBody(WriteAcknowledge msg, ByteBuf out) throws IOException {
                    // Filename
                    byte[] filenameBytes = msg.filename.getBytes();
                    out.writeInt(filenameBytes.length);
                    out.writeBytes(filenameBytes);

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
                public WriteAcknowledge deserializeBody(ByteBuf in) throws IOException {
                    // Filename
                    int len = in.readInt();
                    byte[] buffer = new byte[len];
                    in.readBytes(buffer);
                    String filename = new String(buffer);

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

                    return new WriteAcknowledge(filename, success, server);
                }
            };

    @Override
    public SignedMessageSerializer<? extends SignedProtoMessage> getSerializer() {
        return WriteAcknowledge.serializer;
    }

}
