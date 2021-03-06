package net.realtoner.securityapp.security.handshaking;

import net.realtoner.securityapp.communication.RawMessageManager;
import net.realtoner.securityapp.security.ConnectionInfo;
import net.realtoner.securityapp.security.exception.HandshakingException;

/**
 * @author RyuIkHan
 * @since 2016. 5. 30.
 */
public interface NegotiationStrategy {

    void processNegotiation(ConnectionInfo connectionInfo, HandShakingContext handShakingContext,
                            RawMessageManager rawMessageManager) throws HandshakingException;
}
