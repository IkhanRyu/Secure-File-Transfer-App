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
import java.util.Arrays;
import java.util.Random;

/**
 * @author RyuIkHan
 * @since 2016. 5. 30.
 */
public class MSCHAPInitialAuthenticationStrategy implements InitialAuthenticationStrategy {

    private UserInfoProvider userInfoProvider = null;

    public UserInfoProvider getUserInfoProvider() {
        return userInfoProvider;
    }

    public void setUserInfoProvider(UserInfoProvider userInfoProvider) {
        this.userInfoProvider = userInfoProvider;
    }

    @Override
    public void processInitialAuthentication(HandShakingContext handShakingContext,
                                             MessageManager messageManager)
            throws HandshakingException, UserNotFoundException {

        Message userIdMessage;

        try {
            userIdMessage = messageManager.receiveMessage();
        } catch (IOException e) {
            throw new HandshakingException(e);
        }

        UserInfo userInfo = userInfoProvider.getUserInfoById(new String(userIdMessage.getMessageBody()));

        // there is no such user
        if (userInfo == null) {
            throw new UserNotFoundException("There is no such user who has id \"" +
                    new String(userIdMessage.getMessageBody()) + "\"");
        }

        String challengeStr = createChallengeString();

        try {
            messageManager.sendMessage(challengeStr.getBytes());
        } catch (IOException e) {
            throw new HandshakingException(e);
        }

        Message clientHashedValueMessage;

        try {
            clientHashedValueMessage = messageManager.receiveMessage();
        } catch (IOException e) {
            throw new HandshakingException(e);
        }

        String challengePasswordStr = createChallengePasswordString(challengeStr, userInfo);
        byte[] ownHashedValue;

        try {
            ownHashedValue = processHashing(challengePasswordStr);
        } catch (NoSuchAlgorithmException e) {
            throw new HandshakingException(e);
        }

        try {
            if (Arrays.equals(clientHashedValueMessage.getMessageBody(), ownHashedValue)) {
                // success case
                messageManager.sendOkMessage();
            } else {
                // bad case
                messageManager.sendErrMessage();

                throw new HandshakingException("Fail to authenticate");
            }

        }catch(IOException e){
            throw new HandshakingException(e);
        }
    }

    private String createChallengeString() {

        Random random = new Random();

        int length = 50 + random.nextInt(50);

        StringBuilder stringBuilder = new StringBuilder();

        for(int i = 0; i < length; i++){
            stringBuilder.append(String.valueOf(random.nextInt(10)));
        }

        return stringBuilder.toString();
    }

    private String createChallengePasswordString(String challengeStr, UserInfo userInfo) {
        return challengeStr + userInfo.getPassword();
    }

    private byte[] processHashing(String str) throws NoSuchAlgorithmException {
        MessageDigest sh = MessageDigest.getInstance("SHA-256");

        sh.update(str.getBytes());

        return sh.digest();
    }
}
