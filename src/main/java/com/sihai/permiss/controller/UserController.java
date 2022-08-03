package com.sihai.permiss.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {

    /**
     *  hasPermission('/add','system:user:add')为SpEL表达式
     *  没有指定是哪个对象中的方法，所以执行的是SpEL的RootObject中的方法(SecurityExpressionRoot)
     *
     *  不可用 (DenyAllPermissionEvaluator) 拒绝所有权限评估器, return false
     *  自定义可用 (CustomPermissionEvaluator) 允许所有权限评估器, return true
     *  重载方法 hasPermission
     *
     *  hasAuthority: 有权限
     *  hasAuthority('system:user:add'), 可以不需要权限评估器, CustomPermissionEvaluator不需要注册到 Spring 容器中 // @Component
     *
     *  判断角色： hasRole
     *  判断权限： hasPermission(需要自定义权限评估器)
     *           hasAuthority(使用默认的判断逻辑)
     *
     * @return
     */
    @RequestMapping("/add")
//    @PreAuthorize("hasPermission('/add','system:user:add')") // 访问权限
//    @PreAuthorize("hasAuthority('system:user:add')")
    @PreAuthorize("hasPermission('system:user:add')")
    public String add(){
        return "add";
    }

    @RequestMapping("/delete")
//    @PreAuthorize("hasPermission('/delete','system:user:delete')") // 访问权限
//    @PreAuthorize("hasAuthority('system:user:delete')")
    @PreAuthorize("hasAnyPermissions('system:user:add','system:user:delete')")
    public String delete(){
        return "delete";
    }

    @RequestMapping("/update")
//    @PreAuthorize("hasPermission('/update','system:user:update')") // 访问权限
//    @PreAuthorize("hasAuthority('system:user:update')")
    @PreAuthorize("hasAllPermissions('system:user:add','system:user:update')")
    public String update(){
        return "update";
    }

    @RequestMapping("/select")
//    @PreAuthorize("hasPermission('/select','system:user:select')") // 访问权限
//    @PreAuthorize("hasAuthority('system:user:select')")
    @PreAuthorize("hasAllPermissions('system:user:add','system:user:select')")
    public String select(){
        return "select";
    }


}
