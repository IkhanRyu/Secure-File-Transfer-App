package net.realtoner.securityapp.security;

import net.realtoner.securityapp.communication.ConnectionLogic;
import net.realtoner.securityapp.communication.MessageManager;
import net.realtoner.securityapp.communication.RawMessageManager;
import net.realtoner.securityapp.communication.RawMessageManagerFactory;
import net.realtoner.securityapp.security.communication.AsymmetryMessageManagerFactory;
import net.realtoner.securityapp.security.communication.SymmetryMessageManagerFactory;
import net.realtoner.securityapp.security.exception.HandshakingException;
import net.realtoner.securityapp.security.exception.SocketConnectionException;
import net.realtoner.securityapp.security.handshaking.HandShakingContext;
import net.realtoner.securityapp.security.handshaking.InitialAuthenticationStrategy;
import net.realtoner.securityapp.security.handshaking.KeyingStrategy;
import net.realtoner.securityapp.security.handshaking.NegotiationStrategy;
import net.realtoner.securityapp.security.key.AsymmetricKeyProvider;
import net.realtoner.securityapp.security.key.SymmetricKeyProvider;

import java.io.IOException;

/**
 * @author ryuikhan
 * @since 2016. 5. 24..
 */
public class SecuritySocketConnection{

    /*
    * key providers
    * */
    private AsymmetricKeyProvider asymmetricKeyProvider = null;
    private SymmetricKeyProvider symmetricKeyProvider = null;

    /*
    * Message manager factories
    * */
    private RawMessageManagerFactory rawMessageManagerFactory = null;
    private AsymmetryMessageManagerFactory asymmetryMessageManagerFactory = null;
    private SymmetryMessageManagerFactory symmetryMessageManagerFactory = null;

    /*
    * fields for handShaking stage strategy
    * */
    private NegotiationStrategy negotiationStrategy = null;
    private InitialAuthenticationStrategy initialAuthenticationStrategy = null;
    private KeyingStrategy keyingStrategy = null;

    /*
    * Fields for server
    * */
    private String serverIP = null;
    private int serverPort;

    /*
    * field for current connection
    * */
    private MessageManager currentMessageManager = null;

    public RawMessageManagerFactory getRawMessageManagerFactory() {
        return rawMessageManagerFactory;
    }

    public void setRawMessageManagerFactory(RawMessageManagerFactory rawMessageManagerFactory) {
        this.rawMessageManagerFactory = rawMessageManagerFactory;
    }

    public AsymmetryMessageManagerFactory getAsymmetryMessageManagerFactory() {
        return asymmetryMessageManagerFactory;
    }

    public void setAsymmetryMessageManagerFactory(AsymmetryMessageManagerFactory asymmetryMessageManagerFactory) {
        this.asymmetryMessageManagerFactory = asymmetryMessageManagerFactory;
    }

    public SymmetryMessageManagerFactory getSymmetryMessageManagerFactory() {
        return symmetryMessageManagerFactory;
    }

    public void setSymmetryMessageManagerFactory(SymmetryMessageManagerFactory symmetryMessageManagerFactory) {
        this.symmetryMessageManagerFactory = symmetryMessageManagerFactory;
    }

    public AsymmetricKeyProvider getAsymmetricKeyProvider() {
        return asymmetricKeyProvider;
    }

    public SymmetricKeyProvider getSymmetricKeyProvider() {
        return symmetricKeyProvider;
    }

    public void setSymmetricKeyProvider(SymmetricKeyProvider symmetricKeyProvider) {
        this.symmetricKeyProvider = symmetricKeyProvider;
    }

    public String getServerIP() {
        return serverIP;
    }

    public void setServerIP(String serverIP) {
        this.serverIP = serverIP;
    }

    public int getServerPort() {
        return serverPort;
    }

    public void setServerPort(int serverPort) {
        this.serverPort = serverPort;
    }

    public void setAsymmetricKeyProvider(AsymmetricKeyProvider asymmetricKeyProvider) {
        this.asymmetricKeyProvider = asymmetricKeyProvider;
    }

    protected void setNegotiationStrategy(NegotiationStrategy negotiationStrategy) {
        this.negotiationStrategy = negotiationStrategy;
    }

    protected void setInitialAuthenticationStrategy(InitialAuthenticationStrategy initialAuthenticationStrategy) {
        this.initialAuthenticationStrategy = initialAuthenticationStrategy;
    }

    public void setKeyingStrategy(KeyingStrategy keyingStrategy) {
        this.keyingStrategy = keyingStrategy;
    }

    public void establishConnection(ConnectionInfo connectionInfo) throws SocketConnectionException {

        HandShakingContext handShakingContext = createHandshakingContext(connectionInfo);

        RawMessageManager rawMessageManager;

        try {
            rawMessageManager = rawMessageManagerFactory.create(serverIP, serverPort);
        } catch (IOException e) {
            throw new SocketConnectionException(e);
        }

        try {
            negotiationStrategy.processNegotiation(connectionInfo, handShakingContext, rawMessageManager);
        } catch (HandshakingException e) {
            throw new SocketConnectionException(e);
        }

        AsymmetricCipher asymmetricCipher;

        try {
            asymmetricCipher = handShakingContext.createAsymmetricCipher();
        } catch(Exception e){
            throw new SocketConnectionException(e);
        }

        MessageManager asymmetryMessageManager =
                asymmetryMessageManagerFactory.create(rawMessageManager, asymmetricCipher);

        try {
            initialAuthenticationStrategy.processInitialAuthentication(handShakingContext, asymmetryMessageManager);
        } catch (Exception e) {
            throw new SocketConnectionException(e);
        }

        try {
            keyingStrategy.processKeying(handShakingContext, asymmetryMessageManager);
        } catch (HandshakingException e) {
            throw new SocketConnectionException(e);
        }

        SymmetricCipher symmetricCipher;

        try {
            symmetricCipher = handShakingContext.createSymmetricCipher();
        } catch (Exception e) {
            throw new SocketConnectionException(e);
        }

        currentMessageManager = symmetryMessageManagerFactory.create(rawMessageManager, symmetricCipher);
    }

    public void execute(ConnectionLogic connectionLogic, String parameter) throws IOException{

        if(currentMessageManager == null){
            throw new IOException("Connection is not established. Call establishConnection()");
        }

        connectionLogic.handle(currentMessageManager, parameter);
    }

    private HandShakingContext createHandshakingContext(ConnectionInfo connectionInfo){


        HandShakingContext handShakingContext = new HandShakingContext(asymmetricKeyProvider, symmetricKeyProvider);

        if(connectionInfo.isUseAuthentication()){
            handShakingContext.setUserId(connectionInfo.getUserId());
            handShakingContext.setPassword(connectionInfo.getPassword());
        }

        return handShakingContext;
    }

    public void close() throws IOException {

    }
}
