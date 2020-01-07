package com.lyd.test;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * @author liyingdan
 * @date 2020/1/6
 */
public class BCryptPasswordEncoderTest {
    public static void main(String[] args) {
        // 测试代码
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

        CharSequence rawPassword = "123";

        for(int i = 0; i < 10; i++) {
            String encodedPassword = encoder.encode(rawPassword);
            System.out.println(encodedPassword);
        }

        System.out.println();

        boolean matches = encoder.matches(rawPassword, "$2a$10$fuepuRAic5/JdboZmyPfweAiJyDNYvLYW3GSGVpAxmwuoMpFi/0B2");
        System.out.println(matches); //true

    }
}
