package net.realtoner.securityapp.security;

/**
 * @author RyuIkHan
 * @since 2016. 5. 30.
 */
public class ConnectionInfo {

    private String asymmetricCipherAlgorithm = null;
    private String symmetricCipherAlgorithm = null;

    private String userId = null;
    private String password = null;
    private boolean useAuthentication;

    public ConnectionInfo(){

    }

    public String getAsymmetricCipherAlgorithm() {
        return asymmetricCipherAlgorithm;
    }

    public void setAsymmetricCipherAlgorithm(String asymmetricCipherAlgorithm) {
        this.asymmetricCipherAlgorithm = asymmetricCipherAlgorithm;
    }

    public String getSymmetricCipherAlgorithm() {
        return symmetricCipherAlgorithm;
    }

    public void setSymmetricCipherAlgorithm(String symmetricCipherAlgorithm) {
        this.symmetricCipherAlgorithm = symmetricCipherAlgorithm;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public boolean isUseAuthentication() {
        return useAuthentication;
    }

    public void setUseAuthentication(boolean useAuthentication) {
        this.useAuthentication = useAuthentication;
    }
}
