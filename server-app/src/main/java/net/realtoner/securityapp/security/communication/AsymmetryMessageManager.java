package net.realtoner.securityapp.security.communication;

import net.realtoner.securityapp.communication.Message;
import net.realtoner.securityapp.communication.MessageManager;
import net.realtoner.securityapp.communication.RawMessageManager;
import net.realtoner.securityapp.security.AsymmetricCipher;

import java.io.IOException;
import java.util.Arrays;

/**
 * @author RyuIkHan
 * @since 2016. 5. 30.
 */
public class AsymmetryMessageManager implements MessageManager {

    private MessageManager messageManager = null;
    private AsymmetricCipher asymmetricCipher = null;

    private static final int BLOCK_SIZE = 117;

    private static final int MAX_MESSAGE_LENGTH_BYTE_LENGTH = 4;
    private int messageLengthByteLength = 2;

    public AsymmetryMessageManager(MessageManager messageManager, AsymmetricCipher asymmetricCipher) {
        this.messageManager = messageManager;
        this.asymmetricCipher = asymmetricCipher;
    }

    /*
    * normal getters & setters
    * */
    public MessageManager getMessageManager() {
        return messageManager;
    }

    public void setMessageManager(MessageManager messageManager) {
        this.messageManager = messageManager;
    }

    public AsymmetricCipher getAsymmetricCipher() {
        return asymmetricCipher;
    }

    public void setAsymmetricCipher(AsymmetricCipher asymmetricCipher) {
        this.asymmetricCipher = asymmetricCipher;
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

        try {
            if (body.length < 2) {
                messageManager.sendMessage(messageBytes);
            } else if (messageBytes.length <= BLOCK_SIZE) {
                messageManager.sendMessage(asymmetricCipher.encryptByClientPublicKey(messageBytes));
            } else {

                int start = 0;

                for (int i = 0; i < messageBytes.length / BLOCK_SIZE + 1; i++) {
                    int tempEndIndex = start + BLOCK_SIZE;
                    byte[] block = Arrays.copyOfRange(messageBytes, start, tempEndIndex > messageBytes.length ?
                            messageBytes.length : tempEndIndex);

                    messageManager.sendMessage(
                            asymmetricCipher.encryptByClientPublicKey(block));

                    start = tempEndIndex;
                }
            }

        } catch (Exception e) {
            throw new IOException(e);
        }
    }

    @Override
    public Message receiveMessage() throws IOException {

        Message message = messageManager.receiveMessage();

        if(message.getBodyLength() < 2){
            return message;
        }

        try {

            byte[] plainText = asymmetricCipher.decryptByOwnPrivateKey(message.getMessageBody());

            int bodyLength = 0x00000000;
            int tempShiftLength = 8 * (getMessageLengthByteLength() - 1);
            int tempMask = 0x000000FF << tempShiftLength;

            for (int i = 0; i < getMessageLengthByteLength(); i++) {
                bodyLength |= ((plainText[i] << tempShiftLength) & tempMask);
                tempShiftLength -= 8;
                tempMask = tempMask >> 8;
            }

            int totalMessageLength = messageLengthByteLength + bodyLength;

            byte[] bodyBytes;

            if(totalMessageLength > BLOCK_SIZE){

                bodyBytes = new byte[bodyLength];

                int startIndex = 0;

                for(int i = messageLengthByteLength; i < plainText.length; i++){
                    bodyBytes[startIndex++] = plainText[i];
                }

                for(int i = 0; i < totalMessageLength / BLOCK_SIZE; i++){
                    message = messageManager.receiveMessage();
                    plainText = asymmetricCipher.decryptByOwnPrivateKey(message.getMessageBody());

                    for(byte p : plainText){
                        bodyBytes[startIndex++] = p;
                    }
                }

            }else{
                bodyBytes = Arrays.copyOfRange(plainText, messageLengthByteLength, totalMessageLength);
            }

            return new Message(getMessageLengthByteLength() + bodyBytes.length,
                    bodyLength, bodyBytes);

        } catch (Exception e) {
            throw new IOException(e);
        }
    }

    public void sendOkMessage() throws IOException {
        sendMessage(RawMessageManager.OK_MESSAGE_BODY);
    }

    public void sendErrMessage() throws IOException {
        sendMessage(RawMessageManager.ERR_MESSAGE_BODY);
    }

    @Override
    public void close() {
        messageManager.close();
    }
}
