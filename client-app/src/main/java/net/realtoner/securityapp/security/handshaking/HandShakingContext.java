package net.realtoner.securityapp.security.handshaking;

import net.realtoner.securityapp.security.AsymmetricCipher;
import net.realtoner.securityapp.security.SymmetricCipher;
import net.realtoner.securityapp.security.key.AsymmetricKeyProvider;
import net.realtoner.securityapp.security.key.SymmetricKeyProvider;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * @author RyuIkHan
 * @since 2016. 5. 30.
 */
public class HandShakingContext {

    /*
    * for Asymmetric cipher
    * */
    private AsymmetricKeyProvider asymmetricKeyProvider = null;

    private String asymmetricCipherAlgorithm = null;

    private PublicKey ownPublicKey = null;
    private PrivateKey ownPrivateKey = null;

    private PublicKey serverPublicKey = null;

    /*
    * for Symmetric cipher
    * */
    private SymmetricKeyProvider symmetricKeyProvider = null;

    private Key symmetricKey = null;
    private String symmetricCipherAlgorithm = null;

    public HandShakingContext(AsymmetricKeyProvider asymmetricKeyProvider, SymmetricKeyProvider symmetricKeyProvider) {
        this.asymmetricKeyProvider = asymmetricKeyProvider;
        this.symmetricKeyProvider = symmetricKeyProvider;
    }

    /*
    * for information of user
    * */
    private String userId = null;
    private String password = null;

    /*
    * getters & setters for Asymmetric algorithm
    * */
    public AsymmetricKeyProvider getAsymmetricKeyProvider() {
        return asymmetricKeyProvider;
    }

    public void setAsymmetricKeyProvider(AsymmetricKeyProvider asymmetricKeyProvider) {
        this.asymmetricKeyProvider = asymmetricKeyProvider;
    }

    public String getAsymmetricCipherAlgorithm() {
        return asymmetricCipherAlgorithm;
    }

    public void setAsymmetricCipherAlgorithm(String asymmetricCipherAlgorithm) {
        this.asymmetricCipherAlgorithm = asymmetricCipherAlgorithm;
    }

    public PublicKey getOwnPublicKey() {
        return ownPublicKey;
    }

    public void setOwnPublicKey(PublicKey ownPublicKey) {
        this.ownPublicKey = ownPublicKey;
    }

    public PrivateKey getOwnPrivateKey() {
        return ownPrivateKey;
    }

    public void setOwnPrivateKey(PrivateKey ownPrivateKey) {
        this.ownPrivateKey = ownPrivateKey;
    }

    public PublicKey getServerPublicKey() {
        return serverPublicKey;
    }

    public void setServerPublicKey(PublicKey serverPublicKey) {
        this.serverPublicKey = serverPublicKey;
    }

    /*
    * getters & setters for Symmetric algorithm
    * */
    public SymmetricKeyProvider getSymmetricKeyProvider() {
        return symmetricKeyProvider;
    }

    public void setSymmetricKeyProvider(SymmetricKeyProvider symmetricKeyProvider) {
        this.symmetricKeyProvider = symmetricKeyProvider;
    }

    public Key getSymmetricKey() {
        return symmetricKey;
    }

    public void setSymmetricKey(Key symmetricKey) {
        this.symmetricKey = symmetricKey;
    }

    public String getSymmetricCipherAlgorithm() {
        return symmetricCipherAlgorithm;
    }

    public void setSymmetricCipherAlgorithm(String symmetricCipherAlgorithm) {
        this.symmetricCipherAlgorithm = symmetricCipherAlgorithm;
    }

    /*
    * getters & setters for information of user
    * */

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public AsymmetricCipher createAsymmetricCipher() throws NoSuchPaddingException, NoSuchAlgorithmException {

        AsymmetricCipher asymmetricCipher = new AsymmetricCipher();

        asymmetricCipher.setCipher(Cipher.getInstance(asymmetricCipherAlgorithm));
        asymmetricCipher.setOwnPrivateKey(ownPrivateKey);
        asymmetricCipher.setOwnPublicKey(ownPublicKey);
        asymmetricCipher.setClientPublicKey(serverPublicKey);

        return asymmetricCipher;
    }

    public SymmetricCipher createSymmetricCipher() throws NoSuchPaddingException, NoSuchAlgorithmException {

        SymmetricCipher symmetricCipher = new SymmetricCipher();

        Cipher cipher;

        if(symmetricCipherAlgorithm.startsWith("AES")){ // AES
            cipher = Cipher.getInstance("AES");
        }else if(symmetricCipherAlgorithm.startsWith("DES")){ // DES
            cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        }else{// 3-DES
            cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        }

        symmetricCipher.setCipher(cipher);
        symmetricCipher.setKey(symmetricKey);

        return symmetricCipher;
    }
}
