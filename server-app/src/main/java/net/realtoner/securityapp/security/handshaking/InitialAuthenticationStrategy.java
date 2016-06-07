package net.realtoner.securityapp.security.handshaking;

import net.realtoner.securityapp.communication.MessageManager;
import net.realtoner.securityapp.security.exception.HandshakingException;
import net.realtoner.securityapp.security.exception.UserNotFoundException;

/**
 * @author RyuIkHan
 * @since 2016. 5. 30.
 */
public interface InitialAuthenticationStrategy {

    void processInitialAuthentication(HandShakingContext handShakingContext, MessageManager messageManager)
            throws HandshakingException, UserNotFoundException;
}
