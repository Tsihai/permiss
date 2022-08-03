package com.sihai.permiss.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
/**
 *  在web层的controller启用注解机制的安全确认
 *  只有加了@EnableGlobalMethodSecurity(prePostEnabled=true)
 *  那么在上面使用的 @PreAuthorize 才会生效
 *
 *  在Spring Security中，注解中，判断权限和判断角色的逻辑是一样的，唯一的区别在于角色有ROLE_前缀，权限则没有前缀
 *  根据 SecurityExpressionRoot 类的定义，可以看到，无论最终是权限还是角色 都调用的是 hasAnyAuthorityName 方法
 *  唯一区别在于第一个参数，如果第一个参数为null，则是权限
 *                      如果第一个参数为ROLE_前缀，则是角色
 */
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    @Bean
    UserDetailsService us() {
        // 基于内存的用户数据库
        InMemoryUserDetailsManager manage = new InMemoryUserDetailsManager();
        manage.createUser(User.withUsername("sihai").password("{noop}123456")
                // 给用户设置角色  role的字符串额外带有一个ROLE_前缀
                .roles("admin")
                // 给用户设置权限，可以添加/删除/修改
                // authorities返回角色和权限
                 .authorities("system:user:add", "system:user:delete", "system:user:update")
                // .authorities("system:user:*")
                .build());
        return manage;
    }

    @Bean
    CustomMethodSecurityExpressionHandler customMethodSecurityExpressionHandler() {
        return new CustomMethodSecurityExpressionHandler();
    }

    /**
     * 安全过滤链 基本功能登录认证
     * @param http
     * @return
     * @throws Exception
     */
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .permitAll();
        return http.build();
    }

}
