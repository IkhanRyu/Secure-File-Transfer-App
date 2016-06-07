package net.realtoner.securityapp.server;

import net.realtoner.securityapp.communication.RawMessageManagerFactory;
import net.realtoner.securityapp.security.SecuritySocketConnectionFactory;
import net.realtoner.securityapp.server.exception.SocketConnectionException;
import net.realtoner.securityapp.thread.ThreadPool;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

/**
 * @author ryuikhan
 * @since 2016. 5. 24..
 */
public class SocketServer {

    private ThreadPool threadPool = null;
    private int port;

    private RawMessageManagerFactory rawMessageMakerFactory = null;

    /*
    * Fields for Security Socket Connection
    * */
    private boolean useSecurityConnection = true;
    private SecuritySocketConnectionFactory securitySocketConnectionFactory = null;

    /*
    * Fields for Normal Socket Connection
    * */
    private SocketConnection socketConnection = null;

    private ServerLogic serverLogic = null;

    /*
    * Constructors
    * */
    public SocketServer(){

    }

    public SocketServer(int port){
        this.port = port;
    }

    public SocketServer(int port, ThreadPool threadPool){
        this(port);
        this.threadPool = threadPool;
    }

    /*
    * Normal Getters & Setters
    * */
    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public ThreadPool getThreadPool() {
        return threadPool;
    }

    public void setThreadPool(ThreadPool threadPool) {
        this.threadPool = threadPool;
    }

    public ServerLogic getServerLogic() {
        return serverLogic;
    }

    public RawMessageManagerFactory getRawMessageMakerFactory() {
        return rawMessageMakerFactory;
    }

    public void setRawMessageMakerFactory(RawMessageManagerFactory rawMessageMakerFactory) {
        this.rawMessageMakerFactory = rawMessageMakerFactory;
    }

    public boolean isUseSecurityConnection() {
        return useSecurityConnection;
    }

    public void setUseSecurityConnection(boolean useSecurityConnection) {
        this.useSecurityConnection = useSecurityConnection;
    }

    public SecuritySocketConnectionFactory getSecuritySocketConnectionFactory() {
        return securitySocketConnectionFactory;
    }

    public void setSecuritySocketConnectionFactory(SecuritySocketConnectionFactory securitySocketConnectionFactory) {
        this.securitySocketConnectionFactory = securitySocketConnectionFactory;
    }

    public SocketConnection getSocketConnection() {
        return socketConnection;
    }

    public void setSocketConnection(SocketConnection socketConnection) {
        this.socketConnection = socketConnection;
    }

    public void setServerLogic(ServerLogic serverLogic) {
        this.serverLogic = serverLogic;
    }

    public void start() throws IOException{

        ServerSocket serverSocket = new ServerSocket(port);

        while(true){
            //System.out.println("Server is ready...");

            final Socket socket = serverSocket.accept();

            System.out.println("New connection is established!");

            threadPool.execute(new Runnable(){
                @Override
                public void run(){
                    try {
                        SocketConnection socketConnection;

                        if(useSecurityConnection){
                            socketConnection = securitySocketConnectionFactory.create();
                        }else{
                            return;
                        }

                        socketConnection.establishConnection(rawMessageMakerFactory.create(socket));

                        socketConnection.execute(serverLogic);

                    }catch(SocketConnectionException | IOException e){
                        e.printStackTrace();
                    } finally {
                        try{ socket.close();}catch(IOException ignored){}
                    }
                }
            });
        }
    }
}
