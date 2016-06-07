package net.realtoner.securityapp.server;

import net.realtoner.securityapp.communication.MessageManager;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * @author ryuikhan
 * @since 2016. 5. 24..
 */
public interface ServerLogic {

    void handle(MessageManager messageManager) throws IOException;
}
