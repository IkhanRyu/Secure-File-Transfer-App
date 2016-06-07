package net.realtoner.securityapp.security.authentication;

/**
 * @author RyuIkHan
 * @since 2016. 5. 30.
 */
public interface UserInfoProvider {

    /**
     *
     * @return information of user which has given id or null if there is no such user.
     * */
    UserInfo getUserInfoById(String id);
}
