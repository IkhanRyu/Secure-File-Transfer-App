package net.realtoner.securityapp.security.communication;

import net.realtoner.securityapp.communication.MessageManager;
import net.realtoner.securityapp.security.SymmetricCipher;

/**
 * @author RyuIkHan
 * @since 2016. 6. 6.
 */
public class SymmetryMessageManagerFactory {

    private int messageLengthByteLength = 2;

    public int getMessageLengthByteLength() {
        return messageLengthByteLength;
    }

    public void setMessageLengthByteLength(int messageLengthByteLength) {
        this.messageLengthByteLength = messageLengthByteLength;
    }

    public SymmetryMessageManager create(MessageManager messageManager, SymmetricCipher symmetricCipher){

        SymmetryMessageManager symmetryMessageManager = new SymmetryMessageManager(messageManager, symmetricCipher);

        symmetryMessageManager.setMessageLengthByteLength(messageLengthByteLength);

        return symmetryMessageManager;
    }
}
