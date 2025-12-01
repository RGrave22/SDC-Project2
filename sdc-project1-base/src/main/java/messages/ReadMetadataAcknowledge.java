package messages;

import pt.unl.fct.di.novasys.babel.generic.signed.SignedMessageSerializer;
import pt.unl.fct.di.novasys.babel.generic.signed.SignedProtoMessage;

public class ReadMetadataAcknowledge extends SignedProtoMessage {
    public final static short MESSAGE_ID = 714;

    public ReadMetadataAcknowledge(short id) {
        super(id);
    }

    @Override
    public SignedMessageSerializer<? extends SignedProtoMessage> getSerializer() {
        return null;
    }
}
