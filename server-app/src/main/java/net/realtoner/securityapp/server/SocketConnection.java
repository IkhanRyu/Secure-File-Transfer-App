package net.realtoner.securityapp.server;

import net.realtoner.securityapp.communication.RawMessageManager;
import net.realtoner.securityapp.server.exception.SocketConnectionException;

import java.io.IOException;

/**
 * @author RyuIkHan
 * @since 2016. 5. 25.
 */
public interface SocketConnection {

    void establishConnection(RawMessageManager rawMessageMaker) throws SocketConnectionException;
    void execute(ServerLogic serverLogic) throws IOException;
}
