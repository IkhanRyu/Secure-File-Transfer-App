package net.realtoner.securityapp.security.authentication;

import net.realtoner.securityapp.communication.Message;
import net.realtoner.securityapp.communication.MessageManager;
import net.realtoner.securityapp.security.exception.HandshakingException;
import net.realtoner.securityapp.security.exception.UserNotFoundException;
import net.realtoner.securityapp.security.handshaking.HandShakingContext;
import net.realtoner.securityapp.security.handshaking.InitialAuthenticationStrategy;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * @author RyuIkHan
 * @since 2016. 6. 6.
 */
public class MSCHAPInitialAuthenticationStrategy implements InitialAuthenticationStrategy{

    @Override
    public void processInitialAuthentication(HandShakingContext handShakingContext, MessageManager messageManager) throws HandshakingException, UserNotFoundException {

        try {
            messageManager.sendMessage(handShakingContext.getUserId().getBytes());
        } catch (IOException e) {
            throw new HandshakingException(e);
        }

        Message challengeStrMessage;

        try {
            challengeStrMessage = messageManager.receiveMessage();
        } catch (IOException e) {
            throw new HandshakingException(e);
        }

        String challengePasswordStr = createChallengePasswordString(new String(challengeStrMessage.getMessageBody()),
                handShakingContext.getPassword());

        try {
            messageManager.sendMessage(processHashing(challengePasswordStr));
        } catch (IOException e) {
            throw new HandshakingException(e);
        } catch(NoSuchAlgorithmException ignored){
            //do nothing, never occurs
        }

        Message resultMessage;

        try {
            resultMessage = messageManager.receiveMessage();

            if(Message.isErrMessage(resultMessage)){
                throw new HandshakingException("Fail to authenticate");
            }

        } catch (IOException e) {
            throw new HandshakingException(e);
        }
    }

    private String createChallengePasswordString(String challengeStr, String password) {
        return challengeStr + password;
    }

    private byte[] processHashing(String str) throws NoSuchAlgorithmException {
        MessageDigest sh = MessageDigest.getInstance("SHA-256");

        sh.update(str.getBytes());

        return sh.digest();
    }
}
