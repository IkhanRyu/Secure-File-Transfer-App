package net.realtoner.securityapp.security.communication;

import net.realtoner.securityapp.communication.RawMessageManager;
import net.realtoner.securityapp.security.AsymmetricCipher;

/**
 * @author RyuIkHan
 * @since 2016. 6. 6.
 */
public class AsymmetryMessageManagerFactory {

    private int messageLengthByteLength = 2;

    public int getMessageLengthByteLength() {
        return messageLengthByteLength;
    }

    public void setMessageLengthByteLength(int messageLengthByteLength) {
        this.messageLengthByteLength = messageLengthByteLength;
    }

    public AsymmetryMessageManager create(RawMessageManager rawMessageManager, AsymmetricCipher asymmetricCipher) {

        AsymmetryMessageManager asymmetryMessageManager =
                new AsymmetryMessageManager(rawMessageManager, asymmetricCipher);

        asymmetryMessageManager.setMessageLengthByteLength(messageLengthByteLength);

        return asymmetryMessageManager;
    }
}
