package com.lyd.config;

import com.lyd.util.CrowdFundingUtils;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;
import sun.security.util.Password;

import java.util.Objects;

/**
 * @author liyingdan
 * @date 2020/1/6
 */
@Service
public class PasswordEncoderService implements PasswordEncoder {
    //对原始明文密码进行加密
    @Override
    public String encode(CharSequence rawPassword) {
        Assert.notNull(rawPassword,"rawPassword can not be null!");
        String password = CrowdFundingUtils.md5(rawPassword.toString());
        return password;
    }

    //将明文密码和密文密码进行比较
    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        Assert.notNull(rawPassword,"rawPassword can not be null!");
        String password = CrowdFundingUtils.md5(rawPassword.toString());
        return Objects.equals(password,encodedPassword);
    }
}
