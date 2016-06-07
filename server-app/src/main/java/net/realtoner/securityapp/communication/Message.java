package net.realtoner.securityapp.communication;

import java.util.Arrays;

/**
 * @author RyuIkHan
 * @since 2016. 6. 6.
 */
public class Message {

    /*
    * meta data
    * */
    private int messageLength;
    private int bodyLength;

    /*
    * body
    * */
    private byte[] messageBody = null;

    public Message(int messageLength, int bodyLength, byte[] messageBody){
        this.messageLength = messageLength;
        this.bodyLength = bodyLength;
        this.messageBody = messageBody;
    }

    public int getMessageLength() {
        return messageLength;
    }

    public void setMessageLength(int messageLength) {
        this.messageLength = messageLength;
    }

    public int getBodyLength() {
        return bodyLength;
    }

    public void setBodyLength(int bodyLength) {
        this.bodyLength = bodyLength;
    }

    public byte[] getMessageBody() {
        return messageBody;
    }

    public void setMessageBody(byte[] messageBody) {
        this.messageBody = messageBody;
    }

    public static boolean isOkMessage(Message message){
        return Arrays.equals(message.getMessageBody(), RawMessageManager.OK_MESSAGE_BODY);
    }

    public static boolean isErrMessage(Message message){
        return Arrays.equals(message.getMessageBody(), RawMessageManager.ERR_MESSAGE_BODY);
    }

    @Override
    public String toString(){
        return "body length : " + bodyLength + "\nbody : " + new String(messageBody);
    }
}
