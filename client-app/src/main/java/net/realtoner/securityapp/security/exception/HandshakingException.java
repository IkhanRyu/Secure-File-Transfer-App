package net.realtoner.securityapp.security.exception;

/**
 * @author RyuIkHan
 * @since 2016. 5. 30.
 */
public class HandshakingException extends Exception{

    public HandshakingException() {
    }

    public HandshakingException(String message) {
        super(message);
    }

    public HandshakingException(String message, Throwable cause) {
        super(message, cause);
    }

    public HandshakingException(Throwable cause) {
        super(cause);
    }

    public HandshakingException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
