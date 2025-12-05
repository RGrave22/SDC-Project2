package messages;

import java.io.IOException;
import java.util.UUID;

import io.netty.buffer.ByteBuf;
import pt.unl.fct.di.novasys.babel.generic.signed.SignedMessageSerializer;
import pt.unl.fct.di.novasys.babel.generic.signed.SignedProtoMessage;

public class ListRequest extends SignedProtoMessage {

    public static final short MESSAGE_ID = 110;

    private final String searchPattern;
    private final UUID requestID;

    public ListRequest(String searchPattern) {
        super(MESSAGE_ID);
        this.searchPattern = searchPattern;
        this.requestID = UUID.randomUUID();
    }

    public ListRequest(String searchPattern, UUID requestID) {
        super(MESSAGE_ID);
        this.searchPattern = searchPattern;
        this.requestID = requestID;
    }

    public String getSearchPattern() {
        return searchPattern;
    }

    public UUID getRequestID() {
        return requestID;
    }

    public static final SignedMessageSerializer<ListRequest> serializer
            = new SignedMessageSerializer<ListRequest>() {

        @Override
        public void serializeBody(ListRequest msg, ByteBuf out) throws IOException {
            byte[] patternBytes = msg.searchPattern.getBytes();
            out.writeInt(patternBytes.length);
            out.writeBytes(patternBytes);

            out.writeLong(msg.requestID.getMostSignificantBits());
            out.writeLong(msg.requestID.getLeastSignificantBits());
        }

        @Override
        public ListRequest deserializeBody(ByteBuf in) throws IOException {
            int len = in.readInt();
            byte[] buff = new byte[len];
            in.readBytes(buff);
            String searchPattern = new String(buff);

            long msb = in.readLong();
            long lsb = in.readLong();
            UUID requestID = new UUID(msb, lsb);

            return new ListRequest(searchPattern, requestID);
        }
    };

    @Override
    public SignedMessageSerializer<? extends SignedProtoMessage> getSerializer() {
        return serializer;
    }
}
