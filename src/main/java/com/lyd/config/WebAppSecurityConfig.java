package com.lyd.config;

import com.lyd.service.AppUserDetailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import sun.security.util.Password;

import javax.sql.DataSource;
import java.awt.image.RescaleOp;

@Configuration
@EnableWebSecurity
public class WebAppSecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private DataSource dataSource;
    @Autowired
    private AppUserDetailService userDetailService;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    protected void configure(AuthenticationManagerBuilder builder) throws Exception {
//        builder
//                .inMemoryAuthentication()
//                .withUser("tom")  //指定登录系统的账号
//                .password("123") //指定账号对应的密码
//                .roles("大师"); //必须设置角色或权限，否则会出现Cannot pass a null GrantedAuthority collection错误

        builder.userDetailsService(userDetailService).passwordEncoder(passwordEncoder);
    }
    protected void configure(HttpSecurity security) throws Exception {
        //创建token库对象
        JdbcTokenRepositoryImpl repository = new JdbcTokenRepositoryImpl();
        repository.setDataSource(dataSource);

        security.authorizeRequests()        //对请求进行授权
                .antMatchers("/layui/**","/index.jsp")   //使用ANT风格设置要授权的URL地址
                .permitAll()                //antMatchers()匹配的请求直接放行
                .antMatchers("/level1/**") //指定要设置权限信息的地址
                .hasRole("学徒") //设置指定的地址所需要的权限（或角色）
                .antMatchers("/level2/**")
                .hasRole("大师")
                .antMatchers("/level3/**")
                .hasRole("宗师")
                .antMatchers("/level3/**")
                .hasAuthority("吐纳真气")
                .anyRequest()               //除了antMatchers()匹配的其他请求
                .authenticated()           //需要认证才可以访问
                .and()
                .formLogin()          // 指定使用表单作为登录方式
                .loginPage("/index.jsp")  //指定登录页地址
                .permitAll()
                .defaultSuccessUrl("/main.html") //登录成功后访问的地址
                .usernameParameter("loginacct") //告诉SpringSecurity登录账号的请求参数名
                .passwordParameter("credential") //告诉SpringSecurity登录密码的请求参数名
                .and()
                .logout() //开启用户登录的功能
                .logoutUrl("/my/app/logout") //设置退出登录URL地址
                .logoutSuccessUrl("/index.jsp") //成功退出登录后前往的地址
                .and()
                .exceptionHandling()
                .accessDeniedPage("/to/no/auth/page.html") //访问被拒绝后前往的页面
                .and()
                .rememberMe() //开启记住我功能
                .tokenRepository(repository); //指定token库

    }
}
