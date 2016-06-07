package net.realtoner.securityapp.security.key;

import net.realtoner.securityapp.security.exception.ProvidingKeyException;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.PrivateKey;

/**
 * @author RyuIkHan
 * @since 2016. 5. 25.
 */
public class FileRSAKeyProvider extends RSAKeyProvider{

    private String privateKeyFilePath = null;

    public String getPrivateKeyFilePath() {
        return privateKeyFilePath;
    }

    public void setPrivateKeyFilePath(String privateKeyFilePath) {
        this.privateKeyFilePath = privateKeyFilePath;
    }

    private String readKeyFile() throws IOException{

        StringBuilder stringBuilder = new StringBuilder();

        FileReader fileReader = new FileReader(new File(privateKeyFilePath));

        char[] buffer = new char[30];
        int readLength;

        while((readLength = fileReader.read(buffer)) != -1){
                stringBuilder.append(buffer,0 ,readLength);
        }

        return stringBuilder.toString();
    }


    @Override
    protected String getKeyString() throws ProvidingKeyException{

        StringBuilder stringBuilder = new StringBuilder();
        FileReader fileReader = null;

        try {
            fileReader = new FileReader(new File(privateKeyFilePath));

            char[] buffer = new char[30];
            int readLength;

            while ((readLength = fileReader.read(buffer)) != -1) {
                stringBuilder.append(buffer, 0, readLength);
            }

            return stringBuilder.toString();

        }catch(IOException e){
            throw new ProvidingKeyException(e);
        }finally {
            try{ if(fileReader != null) fileReader.close(); } catch(IOException ignored) {}
        }
    }

    @Override
    public PrivateKey providePrivateKey() throws ProvidingKeyException{

        String rawPrivateKeyString;

        try{
            rawPrivateKeyString = readKeyFile();
        }catch(IOException e){
            throw new ProvidingKeyException(e);
        }

        return extractKeyFromKeyString(rawPrivateKeyString);
    }
}
