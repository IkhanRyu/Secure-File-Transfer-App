package net.realtoner.securityapp.security.key;

import net.realtoner.securityapp.security.exception.ProvidingKeyException;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * @author ryuikhan
 * @since 2016. 5. 24..
 */
public interface AsymmetricKeyProvider {

    PrivateKey providePrivateKey() throws ProvidingKeyException;
    PublicKey providePublicKey() throws ProvidingKeyException;
}
