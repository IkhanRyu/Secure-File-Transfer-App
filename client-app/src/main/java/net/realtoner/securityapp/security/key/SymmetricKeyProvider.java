package net.realtoner.securityapp.security.key;

import net.realtoner.securityapp.security.exception.ProvidingKeyException;

import java.security.Key;

/**
 * @author ryuikhan
 * @since 2016. 5. 24..
 */
public interface SymmetricKeyProvider {

    Key provideKey(byte[] key, String algorithm) throws ProvidingKeyException;
}
