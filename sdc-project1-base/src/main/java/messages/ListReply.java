package messages;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import io.netty.buffer.ByteBuf;
import pt.unl.fct.di.novasys.babel.generic.signed.SignedMessageSerializer;
import pt.unl.fct.di.novasys.babel.generic.signed.SignedProtoMessage;

public class ListReply extends SignedProtoMessage {

    public static final short MESSAGE_ID = 111;

    private final UUID requestID;
    private final List<String> filenames;

    public ListReply(List<String> filenames) {
        super(MESSAGE_ID);
        this.requestID = UUID.randomUUID() ;
        this.filenames = filenames;
    }

    public ListReply(UUID requestID, List<String> filenames) {
        super(MESSAGE_ID);
        this.requestID = requestID;
        this.filenames = filenames;
    }

    public UUID getRequestID() {
        return requestID;
    }

    public List<String> getFilenames() {
        return filenames;
    }

    public static final SignedMessageSerializer<ListReply> serializer
            = new SignedMessageSerializer<ListReply>() {

        @Override
        public void serializeBody(ListReply msg, ByteBuf out) throws IOException {
            out.writeLong(msg.requestID.getMostSignificantBits());
            out.writeLong(msg.requestID.getLeastSignificantBits());

            out.writeInt(msg.filenames.size());
            for (String filename : msg.filenames) {
                byte[] filenameBytes = filename.getBytes();
                out.writeInt(filenameBytes.length);
                out.writeBytes(filenameBytes);
            }
        }

        @Override
        public ListReply deserializeBody(ByteBuf in) throws IOException {
            long msb = in.readLong();
            long lsb = in.readLong();
            UUID requestID = new UUID(msb, lsb);

            int count = in.readInt();
            List<String> filenames = new ArrayList<>();
            for (int i = 0; i < count; i++) {
                int len = in.readInt();
                byte[] buff = new byte[len];
                in.readBytes(buff);
                filenames.add(new String(buff));
            }

            return new ListReply(requestID, filenames);
        }
    };

    @Override
    public SignedMessageSerializer<? extends SignedProtoMessage> getSerializer() {
        return serializer;
    }
}
