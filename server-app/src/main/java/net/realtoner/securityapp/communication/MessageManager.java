package net.realtoner.securityapp.communication;

import java.io.IOException;

/**
 * @author RyuIkHan
 * @since 2016. 6. 6.
 */
public interface MessageManager {

    void sendMessage(byte[] messageBytes) throws IOException;
    Message receiveMessage() throws IOException;

    void sendOkMessage() throws IOException;
    void sendErrMessage() throws IOException;

    void close();
}
