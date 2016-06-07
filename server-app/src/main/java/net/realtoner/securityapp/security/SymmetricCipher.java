package net.realtoner.securityapp.security;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.security.InvalidKeyException;
import java.security.Key;

/**
 * @author RyuIkHan
 * @since 2016. 6. 6.
 */
public class SymmetricCipher {

    private Cipher cipher = null;

    private Key key = null;

    public SymmetricCipher(){

    }

    public Cipher getCipher() {
        return cipher;
    }

    public void setCipher(Cipher cipher) {
        this.cipher = cipher;
    }

    public Key getKey() {
        return key;
    }

    public void setKey(Key key) {
        this.key = key;
    }

    public byte[] encrypt(byte[] input) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        cipher.init(Cipher.ENCRYPT_MODE, key);

        return cipher.doFinal(input);
    }

    public byte[] decrypt(byte[] input) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        cipher.init(Cipher.DECRYPT_MODE, key);

        return cipher.doFinal(input);
    }
}
