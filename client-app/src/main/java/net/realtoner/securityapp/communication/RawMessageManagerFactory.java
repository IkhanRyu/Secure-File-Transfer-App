package net.realtoner.securityapp.communication;

import java.io.IOException;
import java.net.Socket;

/**
 * @author ryuikhan
 * @since 2016. 5. 25..
 */
public class RawMessageManagerFactory {

    private int messageLengthByteLength = 2;

    public int getMessageLengthByteLength() {
        return messageLengthByteLength;
    }

    public void setMessageLengthByteLength(int messageLengthByteLength) {
        this.messageLengthByteLength = messageLengthByteLength;
    }

    public RawMessageManager create(String ipAddress, int portNumber) throws IOException{
        return new RawMessageManager(new Socket(ipAddress, portNumber), getMessageLengthByteLength());
    }
}
