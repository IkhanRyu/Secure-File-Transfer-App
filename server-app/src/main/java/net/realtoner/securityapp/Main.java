package net.realtoner.securityapp;


import net.realtoner.securityapp.communication.RawMessageManagerFactory;
import net.realtoner.securityapp.security.SecuritySocketConnectionFactory;
import net.realtoner.securityapp.security.authentication.MSCHAPInitialAuthenticationStrategy;
import net.realtoner.securityapp.security.authentication.MemoryUserInfoProvider;
import net.realtoner.securityapp.security.authentication.UserInfo;
import net.realtoner.securityapp.security.authentication.UserInfoProvider;
import net.realtoner.securityapp.security.communication.AsymmetryMessageManagerFactory;
import net.realtoner.securityapp.security.communication.SymmetryMessageManagerFactory;
import net.realtoner.securityapp.security.handshaking.InitialAuthenticationStrategy;
import net.realtoner.securityapp.security.key.AsymmetricKeyProvider;
import net.realtoner.securityapp.security.key.FileRSAKeyProvider;
import net.realtoner.securityapp.security.key.RandomSymmetricKeyProvider;
import net.realtoner.securityapp.security.key.SymmetricKeyProvider;
import net.realtoner.securityapp.server.ServerLogic;
import net.realtoner.securityapp.server.SocketServer;
import net.realtoner.securityapp.thread.ConcurrentThreadPool;
import net.realtoner.securityapp.thread.ThreadPool;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;

import java.io.IOException;

/**
 * @author ryuikhan
 * @since 2016. 5. 23..
 */
@Configuration
@PropertySource("classpath:META-INF/config.properties")
public class Main {

    /*
    * Beans for server
    * */
    private int serverPort = 9999;

    private int threadPoolSize = 20;

    private String privateKeyFilePath = "/Users/RyuIkHan/IdeaProjects/securefiletransferserver/key/private_key.pem";

    @Bean
    protected ThreadPool threadPool(){
        return new ConcurrentThreadPool(threadPoolSize);
    }

    /*
    * Beans for key provider
    * */
    @Bean
    protected AsymmetricKeyProvider asymmetricKeyProvider(){

        FileRSAKeyProvider fileRSAKeyProvider = new FileRSAKeyProvider();

        fileRSAKeyProvider.setPrivateKeyFilePath(privateKeyFilePath);

        return fileRSAKeyProvider;
    }

    @Bean
    protected SymmetricKeyProvider symmetricKeyProvider(){
        return new RandomSymmetricKeyProvider();
    }

    @Bean
    protected ServerLogic serverLogic(){

        FileUploadServerLogic defaultServerLogic = new FileUploadServerLogic();

        defaultServerLogic.setFilePath("/Users/RyuIkHan/IdeaProjects/securefiletransferserver/file/");

        return defaultServerLogic;
    }

    @Bean
    protected RawMessageManagerFactory rawMessageMakerFactory(){

        RawMessageManagerFactory rawMessageMakerFactory = new RawMessageManagerFactory();

        rawMessageMakerFactory.setMessageLengthByteLength(2);

        return rawMessageMakerFactory;
    }

    /*
    * Beans for User
    * */
    protected UserInfoProvider userInfoProvider(){

        MemoryUserInfoProvider memoryUserInfoProvider = new MemoryUserInfoProvider();

        memoryUserInfoProvider.putUser(new UserInfo("testUser", "123"));
        memoryUserInfoProvider.putUser(new UserInfo("user1", "user1"));
        memoryUserInfoProvider.putUser(new UserInfo("user2", "user2"));

        return memoryUserInfoProvider;
    }

    /*
    * Beans for Handshaking
    * */
    @Bean
    protected InitialAuthenticationStrategy initialAuthenticationStrategy(){

        MSCHAPInitialAuthenticationStrategy initialAuthenticationStrategy = new MSCHAPInitialAuthenticationStrategy();

        initialAuthenticationStrategy.setUserInfoProvider(userInfoProvider());

        return initialAuthenticationStrategy;
    }

    /*
    * Beans for Security Connection
    * */
    @Bean
    protected AsymmetryMessageManagerFactory asymmetricMessageManagerFactory(){

        AsymmetryMessageManagerFactory asymmetryMessageManagerFactory = new AsymmetryMessageManagerFactory();

        asymmetryMessageManagerFactory.setMessageLengthByteLength(2);

        return asymmetryMessageManagerFactory;
    }

    @Bean
    protected SymmetryMessageManagerFactory symmetryMessageManagerFactory(){

        SymmetryMessageManagerFactory symmetryMessageManagerFactory = new SymmetryMessageManagerFactory();

        symmetryMessageManagerFactory.setMessageLengthByteLength(2);

        return symmetryMessageManagerFactory;
    }

    @Bean
    protected SecuritySocketConnectionFactory securitySocketConnectionFactory(){

        SecuritySocketConnectionFactory securitySocketConnectionFactory = new SecuritySocketConnectionFactory();

        // set message provider
        securitySocketConnectionFactory.setAsymmetricMessageManagerFactory(asymmetricMessageManagerFactory());
        securitySocketConnectionFactory.setSymmetryMessageManagerFactory(symmetryMessageManagerFactory());

        // set key provider
        securitySocketConnectionFactory.setSymmetricKeyProvider(symmetricKeyProvider());
        securitySocketConnectionFactory.setAsymmetricKeyProvider(asymmetricKeyProvider());

        securitySocketConnectionFactory.setInitialAuthenticationStrategy(initialAuthenticationStrategy());

        return securitySocketConnectionFactory;
    }

    /*
    * Beans for Socket server.
    * */
    @Bean
    protected SocketServer socketServer(){

        SocketServer socketServer = new SocketServer(serverPort, threadPool());

        // for security
        socketServer.setUseSecurityConnection(true);
        socketServer.setServerLogic(serverLogic());
        socketServer.setSecuritySocketConnectionFactory(securitySocketConnectionFactory());

        socketServer.setRawMessageMakerFactory(rawMessageMakerFactory());

        return socketServer;
    }

    /*
    * main logic
    * */

    @Autowired
    private SocketServer socketServer;

    private void run(){

        try {
            socketServer.start();
        }catch(IOException e){
            e.printStackTrace();
        }
    }

    public static void main(String[] args){
        ApplicationContext applicationContext = new AnnotationConfigApplicationContext(Main.class);
        applicationContext.getBean(Main.class).run();
    }
}
