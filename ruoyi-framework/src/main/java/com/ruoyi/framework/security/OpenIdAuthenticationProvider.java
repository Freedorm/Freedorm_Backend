package com.ruoyi.framework.security;

import com.ruoyi.common.core.domain.entity.SysUser;
import com.ruoyi.common.core.domain.model.LoginUser;
import com.ruoyi.system.service.ISysUserService;
import lombok.Getter;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

@Component
public class OpenIdAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private ISysUserService userService;

    @Setter
    @Getter
    private UserDetailsService userDetailsService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String openId = (String) authentication.getPrincipal();

        SysUser user = userService.selectUserByOpenid(openId);
        if (user == null) {
            // 如果用户不存在，可以选择自动注册
            user = new SysUser();
            user.setOpenid(openId);
            user.setUserName("wx_" + System.currentTimeMillis());
            user.setNickName("微信用户" + System.currentTimeMillis());
            user.setPassword("N/A"); // 密码可以设置为不可用
            user.setStatus("0");
            user.setDelFlag("0");
            user.setRoleId(100L);
            userService.insertUser(user);
        }

        if ("1".equals(user.getDelFlag())) {
            throw new InternalAuthenticationServiceException("用户已被删除");
        } else if ("1".equals(user.getStatus())) {
            throw new InternalAuthenticationServiceException("用户已被停用");
        }

        // 构建用户详情
        UserDetails loginUser = this.getUserDetailsService().loadUserByUsername(user.getUserName());
        // 构建新的认证信息
        return new OpenIdAuthenticationToken(loginUser, loginUser.getAuthorities());
    }


    @Override
    public boolean supports(Class<?> authentication) {
        return OpenIdAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
