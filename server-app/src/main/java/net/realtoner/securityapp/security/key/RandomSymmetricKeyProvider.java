package net.realtoner.securityapp.security.key;

import net.realtoner.securityapp.security.exception.ProvidingKeyException;

import javax.crypto.KeyGenerator;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

/**
 * @author RyuIkHan
 * @since 2016. 6. 6.
 */
public class RandomSymmetricKeyProvider implements SymmetricKeyProvider{

    @Override
    public Key provideKey(String algorithm) throws ProvidingKeyException {

        Key key;

        try {
            switch (algorithm) {

                default:
                case AlgorithmConstants.SYMMETRY_AES_128:
                case AlgorithmConstants.SYMMETRY_AES_192:
                case AlgorithmConstants.SYMMETRY_AES_256:
                    key = createAESKey(128);

                    break;
                case AlgorithmConstants.SYMMETRY_DES:
                case AlgorithmConstants.SYMMETRY_3DES:
                    key = createDESKey(algorithm);

                    break;
            }

        }catch(Exception e){
            throw new ProvidingKeyException(e);
        }

        return key;
    }

    private Key createAESKey(int keyLength) throws NoSuchAlgorithmException {

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(keyLength);

        return keyGenerator.generateKey();
    }

    private Key createDESKey(String algorithm) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException {

        KeyGenerator keyGenerator;

        if(algorithm.equals(AlgorithmConstants.SYMMETRY_DES)){
            keyGenerator = KeyGenerator.getInstance("DES");
        }else{
            keyGenerator = KeyGenerator.getInstance("DESede");
        }

        return keyGenerator.generateKey();
    }
}
