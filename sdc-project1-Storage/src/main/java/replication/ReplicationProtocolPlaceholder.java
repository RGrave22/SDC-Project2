package replication;

import java.io.IOException;
import java.util.Properties;

import pt.unl.fct.di.novasys.babel.core.GenericProtocol;
import pt.unl.fct.di.novasys.babel.exceptions.HandlerRegistrationException;
import replication.notifications.DeliverEntryNotification;
import replication.requests.AppendRequest;

public class ReplicationProtocolPlaceholder extends GenericProtocol {

	public final static short PROTO_ID = 900;
	public final static String PROTO_NAME = "FakeReplication";
	
	public ReplicationProtocolPlaceholder() {
		super(PROTO_NAME, PROTO_ID);
	}
	
	@Override
	public void init(Properties props) throws HandlerRegistrationException, IOException {
		
		registerRequestHandler(AppendRequest.REQUEST_ID, this::handleAppendRequest);
		
	}

	public void handleAppendRequest(AppendRequest request, short protoID) {
		
		//This logic is evidently incorrect
		triggerNotification(new DeliverEntryNotification(request.getRequestID(), request.getClientID(), request.getClientRequest(), request.getServerSignature()));
		
	}
	
}
