package messages;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

import io.netty.buffer.ByteBuf;
import pt.unl.fct.di.novasys.babel.generic.signed.SignedMessageSerializer;
import pt.unl.fct.di.novasys.babel.generic.signed.SignedProtoMessage;
import pt.unl.fct.di.novasys.network.data.Host;

public class HelloPublicKey extends SignedProtoMessage {

    public static final short MESSAGE_ID = 720;

    private final Host host;
    private final PublicKey publicKey;

    public HelloPublicKey(Host host, PublicKey publicKey) {
        super(MESSAGE_ID);
        this.host = host;
        this.publicKey = publicKey;
    }

    public Host getHost() {
        return host;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public static final SignedMessageSerializer<HelloPublicKey> serializer
            = new SignedMessageSerializer<HelloPublicKey>() {

        @Override
        public void serializeBody(HelloPublicKey msg, ByteBuf out) throws IOException {
            // Serializa Host
            Host.serializer.serialize(msg.host, out);

            // Serializa PublicKey
            byte[] keyBytes = msg.publicKey.getEncoded();
            out.writeInt(keyBytes.length);
            out.writeBytes(keyBytes);
        }

        @Override
        public HelloPublicKey deserializeBody(ByteBuf in) throws IOException {
            // Deserializa Host
            Host host = Host.serializer.deserialize(in);

            // Deserializa PublicKey
            int keyLen = in.readInt();
            byte[] keyBytes = new byte[keyLen];
            in.readBytes(keyBytes);

            try {
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
                PublicKey publicKey = keyFactory.generatePublic(keySpec);

                return new HelloPublicKey(host, publicKey);
            } catch (Exception e) {
                throw new IOException("Failed to reconstruct PublicKey", e);
            }
        }
    };

    @Override
    public SignedMessageSerializer<? extends SignedProtoMessage> getSerializer() {
        return serializer;
    }
}
