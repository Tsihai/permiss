package com.sihai.permiss.config;

import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import javax.lang.model.element.VariableElement;
import java.io.Serializable;
import java.util.Collection;

/**
 * 自定义权限评估器
 *
 * 将自定义的权限评估器注册到 spring 容器中，就会自动生效
 */
@Component
public class CustomPermissionEvaluator implements PermissionEvaluator {


    // 路径匹配符
    AntPathMatcher antPathMatcher = new AntPathMatcher();

    @Override
    public boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission) {
        // 获取当前用户所具备的所有角色
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        for (GrantedAuthority authority : authorities) {
            // 对比当前用户
            // if (authority.getAuthority().equals(permission)) {
            // 说明当前登录的用户具备当前访问所需要的权限
            //  return true;
            //  }
            // 匹配规则：authority.getAuthority() 就是当前用户的角色 + 路径
            if (antPathMatcher.match(authority.getAuthority(), (String) permission)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType, Object permission) {
        return false;
    }
}
