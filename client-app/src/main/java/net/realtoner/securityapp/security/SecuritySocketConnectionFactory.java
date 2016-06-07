package net.realtoner.securityapp.security;

import net.realtoner.securityapp.communication.*;
import net.realtoner.securityapp.security.communication.AsymmetryMessageManagerFactory;
import net.realtoner.securityapp.security.communication.SymmetryMessageManagerFactory;
import net.realtoner.securityapp.security.exception.HandshakingException;
import net.realtoner.securityapp.security.exception.ProvidingKeyException;
import net.realtoner.securityapp.security.exception.UserNotFoundException;
import net.realtoner.securityapp.security.handshaking.HandShakingContext;
import net.realtoner.securityapp.security.handshaking.InitialAuthenticationStrategy;
import net.realtoner.securityapp.security.handshaking.KeyingStrategy;
import net.realtoner.securityapp.security.handshaking.NegotiationStrategy;
import net.realtoner.securityapp.security.key.AlgorithmConstants;
import net.realtoner.securityapp.security.key.AsymmetricKeyProvider;
import net.realtoner.securityapp.security.key.SymmetricKeyProvider;

import java.io.IOException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

/**
 * @author RyuIkHan
 * @since 2016. 5. 25.
 */
public class SecuritySocketConnectionFactory {

    private String serverIP = null;
    private int serverPort;

    /*
    * Key providers
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
    * HandShaking stage strategy
    * */
    private NegotiationStrategy negotiationStrategy = null;
    private InitialAuthenticationStrategy initialAuthenticationStrategy = null;
    private KeyingStrategy keyingStrategy = null;

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

    /*
            * getters & setters for Handshaking stage strategy
            * */
    public NegotiationStrategy getNegotiationStrategy() {
        return negotiationStrategy;
    }

    public void setNegotiationStrategy(NegotiationStrategy negotiationStrategy) {
        this.negotiationStrategy = negotiationStrategy;
    }

    public InitialAuthenticationStrategy getInitialAuthenticationStrategy() {
        return initialAuthenticationStrategy;
    }

    public void setInitialAuthenticationStrategy(InitialAuthenticationStrategy initialAuthenticationStrategy) {
        this.initialAuthenticationStrategy = initialAuthenticationStrategy;
    }

    public KeyingStrategy getKeyingStrategy() {
        return keyingStrategy;
    }

    public void setKeyingStrategy(KeyingStrategy keyingStrategy) {
        this.keyingStrategy = keyingStrategy;
    }

    public SecuritySocketConnection create() throws IOException{

        SecuritySocketConnection securitySocketConnection = new SecuritySocketConnection();

        // set server config
        securitySocketConnection.setServerIP(serverIP);
        securitySocketConnection.setServerPort(serverPort);

        // set message manager factory
        securitySocketConnection.setRawMessageManagerFactory(rawMessageManagerFactory);
        securitySocketConnection.setAsymmetryMessageManagerFactory(asymmetryMessageManagerFactory);
        securitySocketConnection.setSymmetryMessageManagerFactory(symmetryMessageManagerFactory);

        // set key provider
        securitySocketConnection.setAsymmetricKeyProvider(asymmetricKeyProvider);
        securitySocketConnection.setSymmetricKeyProvider(symmetricKeyProvider);

        // set handshaking strategies
        securitySocketConnection.setNegotiationStrategy(negotiationStrategy == null ?
                new DefaultNegotiationStrategy() : negotiationStrategy);
        securitySocketConnection.setInitialAuthenticationStrategy(initialAuthenticationStrategy == null ?
                new DefaultInitialAuthenticationStrategy() : initialAuthenticationStrategy);
        securitySocketConnection.setKeyingStrategy(keyingStrategy == null ? new DefaultKeyingStrategy() : keyingStrategy);

        return securitySocketConnection;
    }

    class DefaultNegotiationStrategy implements NegotiationStrategy {

        @Override
        public void processNegotiation(ConnectionInfo connectionInfo, HandShakingContext handShakingContext,
                                       RawMessageManager rawMessageManager) throws HandshakingException {

            try {
                decideAsymmetricCipherAlgorithm(connectionInfo, handShakingContext, rawMessageManager);
                decideSymmetricCipherAlgorithm(connectionInfo, handShakingContext, rawMessageManager);
            } catch (IOException e) {
                throw new HandshakingException(e);
            }
            try {
                exchangePublicKey(handShakingContext, rawMessageManager);
            } catch (IOException | ProvidingKeyException e) {
                throw new HandshakingException(e);
            }
        }

        private void decideAsymmetricCipherAlgorithm(ConnectionInfo connectionInfo, HandShakingContext handShakingContext,
                                                     RawMessageManager rawMessageManager) throws IOException {

            byte[] messageBody = new byte[1];
            String asymmetricCipherAlgorithm;

            switch(connectionInfo.getAsymmetricCipherAlgorithm()){

                default:
                case AlgorithmConstants.ASYMMETRY_RSA:
                    messageBody[0] = 1;
                    asymmetricCipherAlgorithm = AlgorithmConstants.ASYMMETRY_RSA;
                    break;
            }

            rawMessageManager.sendMessage(messageBody);
            handShakingContext.setAsymmetricCipherAlgorithm(asymmetricCipherAlgorithm);

            Message message = rawMessageManager.receiveMessage();

            if(!Message.isOkMessage(message)){
                throw new IOException("Something is wrong. Server does not send Ok message. " +
                        "At Deciding asymmetric algorithm phase.");
            }
        }

        private void decideSymmetricCipherAlgorithm(ConnectionInfo connectionInfo,
                                                    HandShakingContext handShakingContext,
                                                    RawMessageManager rawMessageManager) throws IOException{

            byte[] messageBody = new byte[1];
            String symmetricCipherAlgorithm;

            switch(connectionInfo.getSymmetricCipherAlgorithm()){

                default:
                case AlgorithmConstants.SYMMETRY_AES_128: // AES 128
                    symmetricCipherAlgorithm = AlgorithmConstants.SYMMETRY_AES_128;
                    messageBody[0] = 0;
                    break;
                case AlgorithmConstants.SYMMETRY_AES_192: // AES 192
                    messageBody[0] = 1;
                    symmetricCipherAlgorithm = AlgorithmConstants.SYMMETRY_AES_192;
                    break;
                case AlgorithmConstants.SYMMETRY_AES_256: // AES 256
                    messageBody[0] = 2;
                    symmetricCipherAlgorithm = AlgorithmConstants.SYMMETRY_AES_256;
                    break;
                case AlgorithmConstants.SYMMETRY_DES: // DES
                    messageBody[0] = 3;
                    symmetricCipherAlgorithm = AlgorithmConstants.SYMMETRY_DES;
                    break;
                case AlgorithmConstants.SYMMETRY_3DES: // 3DES
                    messageBody[0] = 4;
                    symmetricCipherAlgorithm = AlgorithmConstants.SYMMETRY_3DES;
                    break;
                case AlgorithmConstants.SYMMETRY_RC4: // RC4
                    messageBody[0] = 5;
                    symmetricCipherAlgorithm = AlgorithmConstants.SYMMETRY_RC4;
            }

            rawMessageManager.sendMessage(messageBody);
            handShakingContext.setSymmetricCipherAlgorithm(symmetricCipherAlgorithm);

            Message message = rawMessageManager.receiveMessage();

            if(!Message.isOkMessage(message)){
                throw new IOException("Something is wrong. Server does not send Ok message. " +
                        "At Deciding symmetric algorithm phase.");
            }
        }

        private void exchangePublicKey(HandShakingContext handShakingContext, RawMessageManager rawMessageManager)
                throws IOException, ProvidingKeyException{

            PrivateKey ownPrivateKey = handShakingContext.getAsymmetricKeyProvider().providePrivateKey();
            PublicKey ownPublicKey = handShakingContext.getAsymmetricKeyProvider().providePublicKey();

            // send own public key
            rawMessageManager.sendMessage(ownPublicKey.getEncoded());

            // receive server's public key
            Message message = rawMessageManager.receiveMessage();

            PublicKey serverPublicKey;

            try {
                serverPublicKey = KeyFactory.getInstance(handShakingContext.getAsymmetricCipherAlgorithm())
                        .generatePublic(new X509EncodedKeySpec(message.getMessageBody()));
            } catch(Exception e){
                throw new IOException(e);
            }

            handShakingContext.setOwnPrivateKey(ownPrivateKey);
            handShakingContext.setOwnPublicKey(ownPublicKey);
            handShakingContext.setServerPublicKey(serverPublicKey);
        }
    }

    class DefaultInitialAuthenticationStrategy implements InitialAuthenticationStrategy {


        @Override
        public void processInitialAuthentication(HandShakingContext handShakingContext, MessageManager messageManager) throws HandshakingException, UserNotFoundException {
            // do nothing
        }


    }

    class DefaultKeyingStrategy implements KeyingStrategy {

        @Override
        public void processKeying(HandShakingContext handShakingContext, MessageManager messageManager)
                throws HandshakingException {
            try {
                getSymmetricKey(handShakingContext, messageManager);
            } catch (IOException e) {
                throw new HandshakingException(e);
            }

        }

        private void getSymmetricKey(HandShakingContext handShakingContext, MessageManager messageManager) throws IOException{

            Message symmetricKeyMessage = messageManager.receiveMessage();
            byte[] keyBytes = symmetricKeyMessage.getMessageBody();

            Key key;

            try {
                key = handShakingContext.getSymmetricKeyProvider().provideKey(keyBytes,
                        handShakingContext.getSymmetricCipherAlgorithm());
            } catch (ProvidingKeyException e) {
                throw new IOException(e);
            }

            handShakingContext.setSymmetricKey(key);
        }
    }
}
