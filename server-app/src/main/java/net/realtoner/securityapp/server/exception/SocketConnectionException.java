package net.realtoner.securityapp.server.exception;

/**
 * @author RyuIkHan
 * @since 2016. 5. 25.
 */
public class SocketConnectionException extends Exception{

    public SocketConnectionException() {
    }

    public SocketConnectionException(String message) {
        super(message);
    }

    public SocketConnectionException(String message, Throwable cause) {
        super(message, cause);
    }

    public SocketConnectionException(Throwable cause) {
        super(cause);
    }

    public SocketConnectionException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
