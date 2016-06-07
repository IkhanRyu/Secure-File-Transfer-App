package net.realtoner.securityapp.security.key;

import net.realtoner.securityapp.security.exception.ProvidingKeyException;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

/**
 * @author RyuIkHan
 * @since 2016. 6. 6.
 */
public class DefaultSymmetricKeyProvider implements SymmetricKeyProvider{

    @Override
    public Key provideKey(byte[] keyBytes, String algorithm) throws ProvidingKeyException {

        Key key;

        try {
            switch (algorithm) {

                default:
                case AlgorithmConstants.SYMMETRY_AES_128:
                case AlgorithmConstants.SYMMETRY_AES_192:
                case AlgorithmConstants.SYMMETRY_AES_256:
                    key = createAESKey(keyBytes);

                    break;
                case AlgorithmConstants.SYMMETRY_DES:
                case AlgorithmConstants.SYMMETRY_3DES:
                    key = createDESKey(keyBytes, algorithm);
                    break;

            }
        }catch(Exception e){
            throw new ProvidingKeyException(e);
        }

        return key;
    }

    private Key createAESKey(byte[] key){
        return new SecretKeySpec(key, "AES");
    }

    private Key createDESKey(byte[] key, String algorithm) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException {

        KeySpec keySpec;
        SecretKeyFactory secretKeyFactory;

        if(algorithm.equals(AlgorithmConstants.SYMMETRY_DES)){

            keySpec = new DESKeySpec(key);
            secretKeyFactory = SecretKeyFactory.getInstance("DES");

        }else{

            keySpec = new DESedeKeySpec(key);
            secretKeyFactory = SecretKeyFactory.getInstance("DESede");
        }

        return secretKeyFactory.generateSecret(keySpec);
    }
}
