package net.realtoner.securityapp;

import net.realtoner.securityapp.communication.ConnectionLogic;
import net.realtoner.securityapp.communication.RawMessageManagerFactory;
import net.realtoner.securityapp.security.ConnectionInfo;
import net.realtoner.securityapp.security.ConnectionInfoBuilder;
import net.realtoner.securityapp.security.SecuritySocketConnection;
import net.realtoner.securityapp.security.SecuritySocketConnectionFactory;
import net.realtoner.securityapp.security.authentication.MSCHAPInitialAuthenticationStrategy;
import net.realtoner.securityapp.security.communication.AsymmetryMessageManagerFactory;
import net.realtoner.securityapp.security.communication.SymmetryMessageManagerFactory;
import net.realtoner.securityapp.security.exception.SocketConnectionException;
import net.realtoner.securityapp.security.handshaking.InitialAuthenticationStrategy;
import net.realtoner.securityapp.security.key.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;
import java.io.InputStream;
import java.util.Scanner;

/**
 * @author RyuIkHan
 * @since 2016. 5. 26.
 */
@Configuration
public class Main {

    private String serverIP = "127.0.0.1";
    private int serverPort = 9999;

    @Bean
    protected RawMessageManagerFactory rawMessageManagerFactory() {

        RawMessageManagerFactory rawMessageManagerFactory = new RawMessageManagerFactory();

        rawMessageManagerFactory.setMessageLengthByteLength(2);

        return rawMessageManagerFactory;
    }

    private String privateKeyFilePath = "/Users/RyuIkHan/IdeaProjects/SecurityFileTransferClient/key/private_key.pem";

    /*
    * Beans for Key providers
    * */
    @Bean
    protected AsymmetricKeyProvider asymmetricKeyProvider() {

        FileRSAKeyProvider fileRSAKeyProvider = new FileRSAKeyProvider();

        fileRSAKeyProvider.setPrivateKeyFilePath(privateKeyFilePath);

        return fileRSAKeyProvider;
    }

    @Bean
    protected SymmetricKeyProvider symmetricKeyProvider() {
        return new DefaultSymmetricKeyProvider();
    }

    @Bean
    protected InitialAuthenticationStrategy initialAuthenticationStrategy() {

        MSCHAPInitialAuthenticationStrategy initialAuthenticationStrategy = new MSCHAPInitialAuthenticationStrategy();

        return initialAuthenticationStrategy;
    }

    @Bean
    protected AsymmetryMessageManagerFactory asymmetryMessageManagerFactory() {

        AsymmetryMessageManagerFactory asymmetryMessageManagerFactory = new AsymmetryMessageManagerFactory();

        asymmetryMessageManagerFactory.setMessageLengthByteLength(2);

        return asymmetryMessageManagerFactory;
    }

    @Bean
    protected SymmetryMessageManagerFactory symmetryMessageManagerFactory() {

        SymmetryMessageManagerFactory symmetryMessageManagerFactory = new SymmetryMessageManagerFactory();

        symmetryMessageManagerFactory.setMessageLengthByteLength(2);

        return symmetryMessageManagerFactory;
    }

    @Bean
    protected ConnectionLogic connectionLogic() {

        FileUploadLogic fileUploadLogic = new FileUploadLogic();

        return fileUploadLogic;
    }

    @Bean
    protected SecuritySocketConnectionFactory securitySocketConnectionFactory() {

        SecuritySocketConnectionFactory securitySocketConnectionFactory = new SecuritySocketConnectionFactory();

        securitySocketConnectionFactory.setServerIP(serverIP);
        securitySocketConnectionFactory.setServerPort(serverPort);

        securitySocketConnectionFactory.setRawMessageManagerFactory(rawMessageManagerFactory());
        securitySocketConnectionFactory.setAsymmetryMessageManagerFactory(asymmetryMessageManagerFactory());
        securitySocketConnectionFactory.setSymmetryMessageManagerFactory(symmetryMessageManagerFactory());

        securitySocketConnectionFactory.setAsymmetricKeyProvider(asymmetricKeyProvider());
        securitySocketConnectionFactory.setSymmetricKeyProvider(symmetricKeyProvider());

        securitySocketConnectionFactory.setInitialAuthenticationStrategy(initialAuthenticationStrategy());

        return securitySocketConnectionFactory;
    }

    @Bean
    protected InputStream inputStream() {
        return System.in;
    }

    @Bean
    protected Scanner scanner() {
        return new Scanner(inputStream());
    }

    @Autowired
    private SecuritySocketConnectionFactory securitySocketConnectionFactory;

    @Autowired
    private ConnectionLogic connectionLogic;

    @Autowired
    private Scanner scanner;

    private void run() {

        System.out.print("Enter encryption type(1.AES 2.DES 3. 3DES, default : AES) : ");

        String encryptionType;

        encryptionType=scanner.nextLine();

        String cipherAlgorithm;

        switch(encryptionType){

            default:
            case "1":
                cipherAlgorithm = AlgorithmConstants.SYMMETRY_AES_128;

                break;
            case "2":
                cipherAlgorithm = AlgorithmConstants.SYMMETRY_DES;

                break;
            case "3":
                cipherAlgorithm = AlgorithmConstants.SYMMETRY_3DES;

        }

        System.out.println("You select " + cipherAlgorithm + ".");

        System.out.print("Enter your id : ");
        String id = scanner.nextLine();

        System.out.print("Enter your password : ");
        String password = scanner.nextLine();

        try {

            ConnectionInfo connectionInfo = ConnectionInfoBuilder.create()
                    .setAsymmetricAlgorithm(cipherAlgorithm)
                    .setSymmetricAlgorithm(cipherAlgorithm)
                    .setUseAuthentication(true)
                    .setUserId(id)
                    .setPassword(password)
                    .build();

            SecuritySocketConnection securitySocketConnection = securitySocketConnectionFactory.create();

            securitySocketConnection.establishConnection(connectionInfo);

            securitySocketConnection.execute(connectionLogic, "/Users/RyuIkHan/Downloads/testVideo.wmv");

        } catch (IOException e) {
            e.printStackTrace();
        } catch (SocketConnectionException e) {
            e.printStackTrace();
        }

    }

    public static void main(String[] args) {

        ApplicationContext applicationContext = new AnnotationConfigApplicationContext(Main.class);

        applicationContext.getBean(Main.class).run();
    }
}
