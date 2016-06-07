package net.realtoner.securityapp.security;

import net.realtoner.securityapp.communication.Message;
import net.realtoner.securityapp.communication.MessageManager;
import net.realtoner.securityapp.communication.RawMessageManager;
import net.realtoner.securityapp.security.communication.AsymmetryMessageManagerFactory;
import net.realtoner.securityapp.security.communication.SymmetryMessageManagerFactory;
import net.realtoner.securityapp.security.exception.HandshakingException;
import net.realtoner.securityapp.security.exception.ProvidingKeyException;
import net.realtoner.securityapp.security.handshaking.HandShakingContext;
import net.realtoner.securityapp.security.handshaking.InitialAuthenticationStrategy;
import net.realtoner.securityapp.security.handshaking.KeyingStrategy;
import net.realtoner.securityapp.security.handshaking.NegotiationStrategy;
import net.realtoner.securityapp.security.key.AlgorithmConstants;
import net.realtoner.securityapp.security.key.AsymmetricKeyProvider;
import net.realtoner.securityapp.security.key.SymmetricKeyProvider;
import net.realtoner.securityapp.server.ServerLogic;

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

    private AsymmetricKeyProvider asymmetricKeyProvider = null;
    private SymmetricKeyProvider symmetricKeyProvider = null;

    private AsymmetryMessageManagerFactory asymmetricMessageManagerFactory = null;
    private SymmetryMessageManagerFactory symmetryMessageManagerFactory = null;

    /*
    * HandShaking stage strategy
    * */
    private NegotiationStrategy negotiationStrategy = null;
    private InitialAuthenticationStrategy initialAuthenticationStrategy = null;
    private KeyingStrategy keyingStrategy = null;

    public AsymmetricKeyProvider getAsymmetricKeyProvider() {
        return asymmetricKeyProvider;
    }

    public void setAsymmetricKeyProvider(AsymmetricKeyProvider asymmetricKeyProvider) {
        this.asymmetricKeyProvider = asymmetricKeyProvider;
    }

    public AsymmetryMessageManagerFactory getAsymmetricMessageManagerFactory() {
        return asymmetricMessageManagerFactory;
    }

    public void setAsymmetricMessageManagerFactory(AsymmetryMessageManagerFactory asymmetricMessageManagerFactory) {
        this.asymmetricMessageManagerFactory = asymmetricMessageManagerFactory;
    }

    public SymmetryMessageManagerFactory getSymmetryMessageManagerFactory() {
        return symmetryMessageManagerFactory;
    }

    public void setSymmetryMessageManagerFactory(SymmetryMessageManagerFactory symmetryMessageManagerFactory) {
        this.symmetryMessageManagerFactory = symmetryMessageManagerFactory;
    }

    public SymmetricKeyProvider getSymmetricKeyProvider() {
        return symmetricKeyProvider;
    }

    public void setSymmetricKeyProvider(SymmetricKeyProvider symmetricKeyProvider) {
        this.symmetricKeyProvider = symmetricKeyProvider;
    }

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

    public SecuritySocketConnection create() {

        SecuritySocketConnection securitySocketConnection = new SecuritySocketConnection();

        securitySocketConnection.setAsymmetryMessageManagerFactory(asymmetricMessageManagerFactory);
        securitySocketConnection.setSymmetryMessageManagerFactory(symmetryMessageManagerFactory);

        // set key providers
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

    static class DefaultNegotiationStrategy implements NegotiationStrategy {

        @Override
        public void processNegotiation(HandShakingContext handShakingContext, RawMessageManager rawMessageManager)
                throws HandshakingException {

            try {
                decideAsymmetricCipher(handShakingContext, rawMessageManager);
                decideSymmetricCipher(handShakingContext, rawMessageManager);
            } catch (IOException e) {
                throw new HandshakingException(e);
            }

            try {
                exchangePublicKey(handShakingContext, rawMessageManager);
            } catch (Exception e) {
                throw new HandshakingException(e);
            }
        }

        private void decideAsymmetricCipher(HandShakingContext handShakingContext,
                                            RawMessageManager rawMessageManager) throws IOException {

            Message message = rawMessageManager.receiveMessage();

            switch(message.getMessageBody()[0]){
                default:
                case 0: // RSA
                    handShakingContext.setAsymmetricCipherAlgorithm(AlgorithmConstants.ASYMMETRY_RSA);
                    break;
            }

            rawMessageManager.sendOkMessage();
        }

        private void decideSymmetricCipher(HandShakingContext handShakingContext, RawMessageManager rawMessageManager) throws IOException {

            Message message = rawMessageManager.receiveMessage();

            switch(message.getMessageBody()[0]){

                default:
                case 0: // AES 128
                    handShakingContext.setSymmetricCipherAlgorithm(AlgorithmConstants.SYMMETRY_AES_128);
                    break;
                case 1: // AES 192
                    handShakingContext.setSymmetricCipherAlgorithm(AlgorithmConstants.SYMMETRY_AES_192);
                    break;
                case 2: // AES 256
                    handShakingContext.setSymmetricCipherAlgorithm(AlgorithmConstants.SYMMETRY_AES_256);
                    break;
                case 3: // DES
                    handShakingContext.setSymmetricCipherAlgorithm(AlgorithmConstants.SYMMETRY_DES);
                    break;
                case 4: // 3DES
                    handShakingContext.setSymmetricCipherAlgorithm(AlgorithmConstants.SYMMETRY_3DES);
                    break;
                case 5: // RC4
                    handShakingContext.setSymmetricCipherAlgorithm(AlgorithmConstants.SYMMETRY_RC4);
            }

            rawMessageManager.sendOkMessage();
        }

        private void exchangePublicKey(HandShakingContext handShakingContext, RawMessageManager rawMessageManager)
                throws IOException, ProvidingKeyException {

            PrivateKey serverPrivateKey = handShakingContext.getAsymmetricKeyProvider().providePrivateKey();
            PublicKey serverPublicKey = handShakingContext.getAsymmetricKeyProvider().providePublicKey();

            // receive message which contains client's public key
            Message message = rawMessageManager.receiveMessage();

            PublicKey clientPublicKey;

            try {
                clientPublicKey = KeyFactory.getInstance(handShakingContext.getAsymmetricCipherAlgorithm())
                        .generatePublic(new X509EncodedKeySpec(message.getMessageBody()));
            } catch(Exception e){
                throw new IOException(e);
            }

            // send own public key
            rawMessageManager.sendMessage(serverPublicKey.getEncoded());

            handShakingContext.setClientPublicKey(clientPublicKey);
            handShakingContext.setOwnPrivateKey(serverPrivateKey);
            handShakingContext.setOwnPublicKey(serverPublicKey);
        }
    }

    static class DefaultInitialAuthenticationStrategy implements InitialAuthenticationStrategy {

        @Override
        public void processInitialAuthentication(HandShakingContext handShakingContext, MessageManager messageManager) throws HandshakingException {
            //do nothing
        }
    }

    static class DefaultKeyingStrategy implements KeyingStrategy {

        @Override
        public void processKeying(HandShakingContext handShakingContext, MessageManager messageManager) throws IOException {
            sendSymmetricKey(handShakingContext, messageManager);
        }

        private void sendSymmetricKey(HandShakingContext handShakingContext, MessageManager messageManager) throws IOException{

            Key key;

            try {
                key = handShakingContext.getSymmetricKeyProvider()
                        .provideKey(handShakingContext.getSymmetricCipherAlgorithm());
            } catch (ProvidingKeyException e) {
                throw new IOException(e);
            }

            handShakingContext.setSymmetricKey(key);

            messageManager.sendMessage(key.getEncoded());
        }
    }
}
