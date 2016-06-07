package net.realtoner.securityapp.security.authentication;

/**
 * @author RyuIkHan
 * @since 2016. 5. 30.
 */
public class UserInfo {

    private String id = null;
    private String password = null;

    public UserInfo(){

    }

    public UserInfo(String id, String password){
        this.id = id;
        this.password = password;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
