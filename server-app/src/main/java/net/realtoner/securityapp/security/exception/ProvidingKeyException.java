package net.realtoner.securityapp.security.exception;

/**
 * @author RyuIkHan
 * @since 2016. 5. 25.
 */
public class ProvidingKeyException extends Exception{

    public ProvidingKeyException() {
    }

    public ProvidingKeyException(String message) {
        super(message);
    }

    public ProvidingKeyException(String message, Throwable cause) {
        super(message, cause);
    }

    public ProvidingKeyException(Throwable cause) {
        super(cause);
    }

    public ProvidingKeyException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
