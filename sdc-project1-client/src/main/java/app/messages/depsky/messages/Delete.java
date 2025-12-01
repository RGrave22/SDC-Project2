package app.messages.depsky.messages;

import pt.unl.fct.di.novasys.babel.generic.signed.SignedMessageSerializer;
import pt.unl.fct.di.novasys.babel.generic.signed.SignedProtoMessage;

public class Delete extends SignedProtoMessage {
    public final static short MESSAGE_ID = 731;

    public Delete(short id) {
        super(MESSAGE_ID);
    }

    @Override
    public SignedMessageSerializer<? extends SignedProtoMessage> getSerializer() {
        return null;
    }
}
