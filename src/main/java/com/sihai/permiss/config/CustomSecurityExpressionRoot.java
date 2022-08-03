package com.sihai.permiss.config;

import org.springframework.security.access.expression.SecurityExpressionRoot;
import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.AntPathMatcher;

import java.util.Collection;

/**
 * 权限注解自定义表达式
 * 权限判断逻辑
 */
public class CustomSecurityExpressionRoot extends SecurityExpressionRoot implements MethodSecurityExpressionOperations {

    // 通配符
    AntPathMatcher antPathMatcher = new AntPathMatcher();
    // 过滤对象
    private Object filterObject;
    // 返回对象
    private Object returnObject;

    /**
     * Creates a new instance
     *
     * @param authentication the {@link Authentication} to use. Cannot be null.
     */
    public CustomSecurityExpressionRoot(Authentication authentication) {
        super(authentication);
    }

    /**
     * 自定义判断方法
     * 判断是否有某一个权限
     *
     * @param permission
     * @return
     */
    public boolean hasPermission(String permission) {
        // 获取当前登录用户所具备的权限
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        for (GrantedAuthority authority : authorities) {
            if (antPathMatcher.match(authority.getAuthority(), permission)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 判断是否具备多个权限中的任意一个权限
     *
     * @param permissions
     * @return
     */
    public boolean hasAnyPermissions(String... permissions) {
        // 如果权限为空或者长度为0，则返回false
        if (permissions == null || permissions.length == 0) {
            return false;
        }
        // 获取当前登录用户所具备的权限
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        for (GrantedAuthority authority : authorities) {// 遍历
            for (String permission : permissions) {
                if (antPathMatcher.match(authority.getAuthority(), permission)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * 判断是否具备所有权限
     *
     * @param permissions
     * @return
     */
    public boolean hasAllPermissions(String... permissions) {
        // 获取当前登录用户所具备的权限
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        if (permissions == null || permissions.length == 0) {
            return false;
        }
        for (String permission : permissions) {
            boolean flag = false;
            for (GrantedAuthority authority : authorities) {
                if (antPathMatcher.match(authority.getAuthority(), permission)) {
                    flag = true;
                }
            }
            if (!flag) {
                return false;
            }
        }
        return true;
    }



    @Override
    public Object getFilterObject() {
        return filterObject;
    }

    @Override
    public void setFilterObject(Object filterObject) {
        this.filterObject = filterObject;
    }

    @Override
    public Object getReturnObject() {
        return returnObject;
    }

    @Override
    public void setReturnObject(Object returnObject) {
        this.returnObject = returnObject;
    }

    @Override
    public Object getThis() {
        return this;
    }
}
