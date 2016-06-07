package net.realtoner.securityapp.communication;

import java.io.IOException;

/**
 * @author RyuIkHan
 * @since 2016. 6. 7.
 */
public interface ConnectionLogic {

    void handle(MessageManager messageManager, String parameter) throws IOException;
}
