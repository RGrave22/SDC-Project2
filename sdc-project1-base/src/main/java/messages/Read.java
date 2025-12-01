package messages;

import io.netty.buffer.ByteBuf;
import pt.unl.fct.di.novasys.babel.generic.signed.SignedMessageSerializer;
import pt.unl.fct.di.novasys.babel.generic.signed.SignedProtoMessage;

import java.io.IOException;

public class Read extends SignedProtoMessage {
    public final static short MESSAGE_ID = 711;

    private final String filename;

    public Read(String filename) {
        super(MESSAGE_ID);
        this.filename = filename;
    }

    public static final SignedMessageSerializer<Read> serializer = new SignedMessageSerializer<Read>() {

        @Override
        public void serializeBody(Read msg, ByteBuf out) throws IOException {

            // Filename
            out.writeInt(msg.filename.length());
            out.writeBytes(msg.filename.getBytes());

        }

        @Override
        public Read deserializeBody(ByteBuf in) throws IOException {

            // Filename
            int len = in.readInt();
            byte[] buffer = new byte[len];
            in.readBytes(buffer);
            String filename = new String(buffer);


            return new Read(filename);
        }
    };

    @Override
    public SignedMessageSerializer<? extends SignedProtoMessage> getSerializer() {
        return Read.serializer;
    }

}
