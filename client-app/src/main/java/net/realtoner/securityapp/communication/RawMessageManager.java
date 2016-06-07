package net.realtoner.securityapp.communication;

import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;

/**
 * @author RyuIkHan
 * @since 2016. 5. 24.
 */
public class RawMessageManager implements MessageManager {

    private Socket socket = null;

    public static final byte[] OK_MESSAGE_BODY = {1, 1, 1, 1, 1, 1, 1, 1};
    public static final byte[] ERR_MESSAGE_BODY = {0, 0, 0, 0, 0, 0, 0, 0};

    private static final int MAX_MESSAGE_LENGTH_BYTE_LENGTH = 4;
    private int messageLengthByteLength = 2;

    private static final int MAX_BUFFER_SIZE = 1024;

    public RawMessageManager(Socket socket, int messageLengthByteLength) {
        this.socket = socket;
        this.messageLengthByteLength = messageLengthByteLength;
    }

    /*
    * Normal getters & setters
    * */

    public Socket getSocket() {
        return socket;
    }

    public void setSocket(Socket socket) {
        this.socket = socket;
    }

    public int getMessageLengthByteLength() {
        return messageLengthByteLength;
    }

    public void setMessageLengthByteLength(int messageLengthByteLength) {

        if (messageLengthByteLength > MAX_MESSAGE_LENGTH_BYTE_LENGTH) {
            this.messageLengthByteLength = MAX_MESSAGE_LENGTH_BYTE_LENGTH;
        } else {
            this.messageLengthByteLength = messageLengthByteLength;
        }
    }

    @Override
    public void sendMessage(byte[] body) throws IOException {

        int messageLength = messageLengthByteLength + body.length;
        byte[] messageBytes = new byte[messageLength];

        int tempMask = 0xFF000000 >>> (8 * (MAX_MESSAGE_LENGTH_BYTE_LENGTH - messageLengthByteLength));
        for (int i = 0; i < messageLengthByteLength; i++) {
            messageBytes[i] |= (body.length & tempMask);
            tempMask = tempMask >>> 8;
        }

        int j = 0;

        for (int i = messageLengthByteLength; i < messageLength; i++) {
            messageBytes[i] = body[j++];
        }

        if (messageLength > MAX_BUFFER_SIZE) {

            int startIndex = 0;

            for (int i = 0; i < messageLength / MAX_BUFFER_SIZE; i++) {
                socket.getOutputStream().write(messageBytes, startIndex, startIndex + MAX_BUFFER_SIZE - 1);
                startIndex += MAX_BUFFER_SIZE;
            }

            if (messageLengthByteLength % MAX_BUFFER_SIZE != 0) {
                socket.getOutputStream().write(messageBytes, startIndex, messageBytes.length - 1);
            }

        } else {
            socket.getOutputStream().write(messageBytes);
        }
    }

    @Override
    public Message receiveMessage() throws IOException {

        InputStream inputStream = getSocket().getInputStream();

        byte[] messageLengthBytes = new byte[getMessageLengthByteLength()];

        if (inputStream.read(messageLengthBytes) == -1) {
            throw new IOException("Invalid message format.");
        }

        int bodyLength = 0x00000000;
        int tempShiftLength = 8 * (getMessageLengthByteLength() - 1);
        int tempMask = 0x000000FF << tempShiftLength;

        for (int i = 0; i < getMessageLengthByteLength(); i++) {
            bodyLength |= ((messageLengthBytes[i] << tempShiftLength) & tempMask);
            tempShiftLength -= 8;
            tempMask = tempMask >> 8;
        }

        byte[] body = new byte[bodyLength];

        if (inputStream.read(body) == -1) {
            throw new IOException("Invalid message format.");
        }

        return new Message(getMessageLengthByteLength() + bodyLength, bodyLength, body);
    }

    public void sendOkMessage() throws IOException {
        sendMessage(OK_MESSAGE_BODY);
    }

    public void sendErrMessage() throws IOException {
        sendMessage(ERR_MESSAGE_BODY);
    }


    @Override
    public void close() {
        try {
            socket.close();
        } catch (IOException ignored) {
        }
    }
}