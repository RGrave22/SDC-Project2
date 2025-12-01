package app.messages.depsky.messages;

import pt.unl.fct.di.novasys.babel.generic.signed.SignedMessageSerializer;
import pt.unl.fct.di.novasys.babel.generic.signed.SignedProtoMessage;

public class ReadMetadata extends SignedProtoMessage {
    public final static short MESSAGE_ID = 713;

    public ReadMetadata(short id) {
        super(id);
    }

    @Override
    public SignedMessageSerializer<? extends SignedProtoMessage> getSerializer() {
        return null;
    }
}
