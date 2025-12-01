package messages;

import pt.unl.fct.di.novasys.babel.generic.signed.SignedMessageSerializer;
import pt.unl.fct.di.novasys.babel.generic.signed.SignedProtoMessage;

public class DeleteAcknowledge extends SignedProtoMessage {
    public final static short MESSAGE_ID = 732;

    public DeleteAcknowledge(short id) {
        super(id);
    }

    @Override
    public SignedMessageSerializer<? extends SignedProtoMessage> getSerializer() {
        return null;
    }
}
