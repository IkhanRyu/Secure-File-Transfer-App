package net.realtoner.securityapp.security;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * @author RyuIkHan
 * @since 2016. 5. 30.
 */
public class AsymmetricCipher {

    private Cipher cipher = null;

    private PrivateKey ownPrivateKey = null;
    private PublicKey ownPublicKey = null;

    private PublicKey clientPublicKey = null;

    public AsymmetricCipher(){

    }

    public Cipher getCipher() {
        return cipher;
    }

    public void setCipher(Cipher cipher) {
        this.cipher = cipher;
    }

    public PrivateKey getOwnPrivateKey() {
        return ownPrivateKey;
    }

    public void setOwnPrivateKey(PrivateKey ownPrivateKey) {
        this.ownPrivateKey = ownPrivateKey;
    }

    public PublicKey getOwnPublicKey() {
        return ownPublicKey;
    }

    public void setOwnPublicKey(PublicKey ownPublicKey) {
        this.ownPublicKey = ownPublicKey;
    }

    public PublicKey getClientPublicKey() {
        return clientPublicKey;
    }

    public void setClientPublicKey(PublicKey clientPublicKey) {
        this.clientPublicKey = clientPublicKey;
    }

    public byte[] encryptByClientPublicKey(byte[] input) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        cipher.init(Cipher.ENCRYPT_MODE, clientPublicKey);
        return cipher.doFinal(input);
    }

    public byte[] decryptByOwnPrivateKey(byte[] input) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        cipher.init(Cipher.DECRYPT_MODE, ownPrivateKey);
        return cipher.doFinal(input);
    }
}
