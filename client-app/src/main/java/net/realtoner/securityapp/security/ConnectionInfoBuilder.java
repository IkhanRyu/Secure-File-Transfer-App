package net.realtoner.securityapp.security;

/**
 * @author RyuIkHan
 * @since 2016. 5. 30.
 */
public class ConnectionInfoBuilder {

    private String asymmetricAlgorithm = null;

    private String symmetricAlgorithm = null;

    private String userId = null;
    private String password = null;
    private boolean useAuthentication = true;

    private ConnectionInfoBuilder(){

    }

    public static ConnectionInfoBuilder create(){
        return new ConnectionInfoBuilder();
    }

    public ConnectionInfoBuilder setAsymmetricAlgorithm(String asymmetricAlgorithm){
        this.asymmetricAlgorithm = asymmetricAlgorithm;

        return this;
    }

    public ConnectionInfoBuilder setSymmetricAlgorithm(String symmetricAlgorithm){
        this.symmetricAlgorithm = symmetricAlgorithm;

        return this;
    }

    public ConnectionInfoBuilder setUserId(String userId){
        this.userId = userId;

        return this;
    }

    public ConnectionInfoBuilder setPassword(String password){
        this.password = password;

        return this;
    }

    public ConnectionInfoBuilder setUseAuthentication(boolean flag){
        useAuthentication = flag;

        return this;
    }

    public ConnectionInfo build(){

        ConnectionInfo connectionInfo = new ConnectionInfo();

        connectionInfo.setAsymmetricCipherAlgorithm(asymmetricAlgorithm);
        connectionInfo.setSymmetricCipherAlgorithm(symmetricAlgorithm);

        if(useAuthentication) {
            connectionInfo.setUserId(userId);
            connectionInfo.setPassword(password);
        }

        connectionInfo.setUseAuthentication(useAuthentication);

        return connectionInfo;
    }
}
