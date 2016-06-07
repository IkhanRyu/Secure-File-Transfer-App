package net.realtoner.securityapp.security.authentication;

import java.util.HashMap;
import java.util.Map;

/**
 * @author RyuIkHan
 * @since 2016. 5. 30.
 */
public class MemoryUserInfoProvider implements UserInfoProvider{

    private final Map<String, UserInfo> userInfoMap = new HashMap<>();

    public void putUser(UserInfo userInfo){
        userInfoMap.put(userInfo.getId(), userInfo);
    }

    @Override
    public UserInfo getUserInfoById(String id) {
        return userInfoMap.get(id);
    }
}
