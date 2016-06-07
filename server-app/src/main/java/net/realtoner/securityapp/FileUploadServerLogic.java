package net.realtoner.securityapp;

import net.realtoner.securityapp.communication.Message;
import net.realtoner.securityapp.communication.MessageManager;
import net.realtoner.securityapp.communication.RawMessageManager;
import net.realtoner.securityapp.server.ServerLogic;

import java.io.*;

/**
 * @author ryuikhan
 * @since 2016. 5. 24..
 */
public class FileUploadServerLogic implements ServerLogic {

    private String filePath = null;

    public String getFilePath() {
        return filePath;
    }

    public void setFilePath(String filePath) {
        this.filePath = filePath;
    }

    @Override
    public void handle(MessageManager messageManager) throws IOException {

        // file size
        Message message = messageManager.receiveMessage();

        long fileSize = Long.valueOf(new String(message.getMessageBody()));

        System.out.println("file size : " + fileSize);

        // file name
        message = messageManager.receiveMessage();

        String fileName = new String(message.getMessageBody());

        System.out.println("file name : " + fileName);

        File outputFile = new File(filePath + fileName);

        FileOutputStream fileOutputStream = new FileOutputStream(outputFile);

        long size = 0;

        while (size != fileSize) {
            message = messageManager.receiveMessage();

            fileOutputStream.write(message.getMessageBody());

            size += message.getBodyLength();
        }

        System.out.println("transfer end!");
    }
}
