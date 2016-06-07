package net.realtoner.securityapp.security;

import net.realtoner.securityapp.communication.Message;
import net.realtoner.securityapp.communication.MessageManager;
import net.realtoner.securityapp.communication.RawMessageManager;
import net.realtoner.securityapp.security.communication.AsymmetryMessageManager;
import net.realtoner.securityapp.security.communication.AsymmetryMessageManagerFactory;
import net.realtoner.securityapp.security.communication.SymmetryMessageManagerFactory;
import net.realtoner.securityapp.security.exception.HandshakingException;
import net.realtoner.securityapp.security.handshaking.HandShakingContext;
import net.realtoner.securityapp.security.handshaking.InitialAuthenticationStrategy;
import net.realtoner.securityapp.security.handshaking.KeyingStrategy;
import net.realtoner.securityapp.security.handshaking.NegotiationStrategy;
import net.realtoner.securityapp.security.key.AsymmetricKeyProvider;
import net.realtoner.securityapp.security.key.SymmetricKeyProvider;
import net.realtoner.securityapp.server.ServerLogic;
import net.realtoner.securityapp.server.SocketConnection;
import net.realtoner.securityapp.server.exception.SocketConnectionException;

import java.io.IOException;

/**
 * @author ryuikhan
 * @since 2016. 5. 24..
 */
public class SecuritySocketConnection implements SocketConnection {

    private AsymmetricKeyProvider asymmetricKeyProvider = null;
    private SymmetricKeyProvider symmetricKeyProvider = null;

    /*
    * fields for handShaking stage strategy
    * */
    private NegotiationStrategy negotiationStrategy = null;
    private InitialAuthenticationStrategy initialAuthenticationStrategy = null;
    private KeyingStrategy keyingStrategy = null;

    /*
    * fields for asymmetric message
    * */
    private AsymmetryMessageManagerFactory asymmetryMessageManagerFactory = null;
    private SymmetryMessageManagerFactory symmetryMessageManagerFactory = null;

    /*
    * field for current connection
    * */
    private MessageManager currentMessageManager = null;

    public AsymmetricKeyProvider getAsymmetricKeyProvider() {
        return asymmetricKeyProvider;
    }

    public void setAsymmetricKeyProvider(AsymmetricKeyProvider asymmetricKeyProvider) {
        this.asymmetricKeyProvider = asymmetricKeyProvider;
    }

    public SymmetricKeyProvider getSymmetricKeyProvider() {
        return symmetricKeyProvider;
    }

    public void setSymmetricKeyProvider(SymmetricKeyProvider symmetricKeyProvider) {
        this.symmetricKeyProvider = symmetricKeyProvider;
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

    @Override
    public void establishConnection(RawMessageManager rawMessageManager) throws SocketConnectionException {

        HandShakingContext handShakingContext = createHandshakingContext();

        // negotiation phase
        try {
            negotiationStrategy.processNegotiation(handShakingContext, rawMessageManager);
        } catch (HandshakingException e) {
            rawMessageManager.close();
            throw new SocketConnectionException(e);
        }

        AsymmetricCipher asymmetricCipher;

        try{
            asymmetricCipher = handShakingContext.createAsymmetricCipher();
        }catch(Exception e){
            rawMessageManager.close();
            throw new SocketConnectionException(e);
        }

        AsymmetryMessageManager asymmetryMessageManager =
                asymmetryMessageManagerFactory.create(rawMessageManager, asymmetricCipher);

        // authentication
        try {
            initialAuthenticationStrategy.processInitialAuthentication(handShakingContext, asymmetryMessageManager);
        } catch (Exception e) {
            asymmetryMessageManager.close();
            throw new SocketConnectionException(e);
        }

        // keying
        try {
            keyingStrategy.processKeying(handShakingContext, asymmetryMessageManager);
        } catch (IOException e) {
            throw new SocketConnectionException(e);
        }

        SymmetricCipher symmetricCipher;

        try {
            symmetricCipher = handShakingContext.createSymmetricCipher();
        }catch(Exception e){
            throw new SocketConnectionException(e);
        }

        currentMessageManager = symmetryMessageManagerFactory.create(rawMessageManager, symmetricCipher);
    }

    @Override
    public void execute(ServerLogic serverLogic) throws IOException{

        if(currentMessageManager == null){
            throw new IOException("Connection is not established. Call establishConnection()");
        }

        serverLogic.handle(currentMessageManager);
    }


    public void close() throws IOException {

    }

    private HandShakingContext createHandshakingContext(){
        return new HandShakingContext(asymmetricKeyProvider, symmetricKeyProvider);
    }
}
