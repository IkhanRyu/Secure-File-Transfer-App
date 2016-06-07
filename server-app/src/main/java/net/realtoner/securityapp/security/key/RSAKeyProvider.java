package net.realtoner.securityapp.security.key;

import net.realtoner.securityapp.security.exception.ProvidingKeyException;
import org.apache.commons.codec.binary.Base64;
import sun.security.rsa.RSAPrivateCrtKeyImpl;
import sun.security.util.DerInputStream;
import sun.security.util.DerValue;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;

/**
 * @author RyuIkHan
 * @since 2016. 5. 25.
 */
public abstract class RSAKeyProvider implements AsymmetricKeyProvider {

    private static final String RSA = "RSA";

    private static final String PKCS1_KEY_HEADER = "-----BEGIN RSA PRIVATE KEY-----";
    private static final String PKCS1_KEY_FOOTER = "-----END RSA PRIVATE KEY-----";

    private static final String PKCS8_HEADER = "-----BEGIN PRIVATE KEY-----";
    private static final String PKCS8_FOOTER = "-----END PRIVATE KEY-----";

    private static final int KEY_CONTENT_ROW_LENGTH = 64;

    protected abstract String getKeyString() throws ProvidingKeyException;

    private PrivateKey cachedPrivateKey = null;

    @Override
    public PrivateKey providePrivateKey() throws ProvidingKeyException {

        String keyString = getKeyString();

        cachedPrivateKey = extractKeyFromKeyString(keyString);

        return cachedPrivateKey;
    }

    @Override
    public PublicKey providePublicKey() throws ProvidingKeyException {

        PrivateKey privateKey = cachedPrivateKey == null ? providePrivateKey() : cachedPrivateKey;

        RSAPrivateCrtKeyImpl rsaPrivateCrtKey = (RSAPrivateCrtKeyImpl)privateKey;

        try {
            return KeyFactory.getInstance(RSA)
                    .generatePublic(new RSAPublicKeySpec(rsaPrivateCrtKey.getModulus(),
                            rsaPrivateCrtKey.getPublicExponent()));
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new ProvidingKeyException(e);
        }
    }

    protected PrivateKey extractKeyFromKeyString(String keyStr) throws ProvidingKeyException {

        byte[] bytes = keyStr.trim().getBytes();

        byte[] headerBytes, contentBytes, footerBytes;

        int headerLength = 0;

        for (byte aByte : bytes) {
            if (aByte == '\n')
                break;

            headerLength += 1;
        }

        int footerLength = 0;

        for (int i = bytes.length - 1; i > 0; i--) {
            if (bytes[i] == '\n')
                break;

            footerLength += 1;
        }

        headerBytes = Arrays.copyOfRange(bytes, 0, headerLength);
        footerBytes = Arrays.copyOfRange(bytes, bytes.length - footerLength, bytes.length);
        contentBytes = eliminateCSLF(Arrays.copyOfRange(bytes, headerLength + 1, bytes.length - footerLength - 1));

        String header = new String(headerBytes);
        String footer = new String(footerBytes);

        PrivateKey privateKey = null;

        switch (header) {

            case PKCS1_KEY_HEADER:

                if (!footer.equals(PKCS1_KEY_FOOTER)) {
                    throw new ProvidingKeyException("Header and Footer are not same type.");
                }

                try {
                    privateKey = createPKCS1PrivateKey(contentBytes);
                } catch (ProvidingKeyException e) {
                    throw e;
                } catch (Exception e) {
                    throw new ProvidingKeyException(e);
                }

                break;

            case PKCS8_HEADER:

                if (!footer.equals(PKCS8_FOOTER)) {
                    throw new ProvidingKeyException("Header and Footer are not same type.");
                }

                break;

            default:
                throw new ProvidingKeyException("Not support key type. Only support not encrypted PKCS#1, PKCS#8.");

        }

        return privateKey;
    }

    private byte[] eliminateCSLF(byte[] input) {

        int numOfCRLF = input.length / KEY_CONTENT_ROW_LENGTH;

        byte[] output = new byte[input.length - numOfCRLF];

        int startIndex = 0;
        int index = 0;

        for (int i = 0; i < numOfCRLF; i++) {
            for (int j = startIndex; j < startIndex + KEY_CONTENT_ROW_LENGTH; j++) {
                output[index++] = input[j];
            }

            startIndex += KEY_CONTENT_ROW_LENGTH + 1;
        }

        for (int i = startIndex; i < input.length; i++) {
            output[index++] = input[i];
        }

        return output;
    }

    private PrivateKey createPKCS1PrivateKey(byte[] keyBytes) throws IOException, NoSuchAlgorithmException, ProvidingKeyException, InvalidKeySpecException {

        DerInputStream derReader = new DerInputStream(Base64.decodeBase64(keyBytes));

        DerValue[] seq = derReader.getSequence(0);

        if (seq.length < 9) {
            throw new ProvidingKeyException("Could not parse a PKCS1 private key.");
        }

        // skip version seq[0];
        BigInteger modulus = seq[1].getBigInteger();
        BigInteger publicExp = seq[2].getBigInteger();
        BigInteger privateExp = seq[3].getBigInteger();
        BigInteger prime1 = seq[4].getBigInteger();
        BigInteger prime2 = seq[5].getBigInteger();
        BigInteger exp1 = seq[6].getBigInteger();
        BigInteger exp2 = seq[7].getBigInteger();
        BigInteger crtCoef = seq[8].getBigInteger();

        RSAPrivateCrtKeySpec keySpec = new RSAPrivateCrtKeySpec(modulus, publicExp, privateExp, prime1, prime2, exp1, exp2, crtCoef);

        KeyFactory factory = KeyFactory.getInstance("RSA");

        return factory.generatePrivate(keySpec);
    }
}
