package com.dy.demo1.config;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    //授权
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //首页所有人可以访问，但是里面的功能页面，只有对应有权限的人才能访问

        //请求授权的规则
        http.authorizeRequests()
                .antMatchers("/").permitAll() //无条件访问
                .antMatchers("/level1/**").hasRole("vip1")
                .antMatchers("/level2/**").hasRole("vip2")
                .antMatchers("/level3/**").hasRole("vip3");

        //没有权限，默认会到登录页面
        http.formLogin().loginPage("/toLogin");

        //防止网站攻击：get,post
        http.csrf().disable();
        //注销,开启了注销功能，跳转到首页
        http.logout().logoutSuccessUrl("/index");

        //开启记住我功能 cookies
        http.rememberMe();
    }

    //认证
    //密码编码：PasswordEncoder
    //在spring security 5.0+新增了很多的加密方法
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //数据正常应该从数据库中读取
        auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder())
                .withUser("dy").password(new BCryptPasswordEncoder().encode("123456")).roles("vip1","vip2")
                .and()
                .withUser("root").password(new BCryptPasswordEncoder().encode("123456")).roles("vip1","vip2","vip3");
    }
}
