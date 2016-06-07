package net.realtoner.securityapp;

import net.realtoner.securityapp.communication.ConnectionLogic;
import net.realtoner.securityapp.communication.MessageManager;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Arrays;

/**
 * @author RyuIkHan
 * @since 2016. 6. 7.
 */
public class FileUploadLogic implements ConnectionLogic {

    private static final int BUFFER_SIZE = 100;

    @Override
    public void handle(MessageManager messageManager, String parameter) throws IOException {

        long startTime = System.currentTimeMillis();

        File file = new File(parameter);

        //send file size
        messageManager.sendMessage(String.valueOf(file.length()).getBytes());

        // send file name
        messageManager.sendMessage(file.getName().getBytes());

        //send file
        byte[] buffer = new byte[BUFFER_SIZE];

        FileInputStream fileInputStream = new FileInputStream(file);

        int readSize;

        while ((readSize = fileInputStream.read(buffer)) != -1) {
            messageManager.sendMessage(Arrays.copyOfRange(buffer, 0, readSize));
        }

        long endTime = System.currentTimeMillis();

        System.out.println("File transfer time : " + String.valueOf(endTime - startTime));
    }
}
