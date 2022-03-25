package com.mj.securitystudy.tests;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Slf4j
@SpringBootTest
public class SimpleTests {

    @Autowired
    private BCryptPasswordEncoder encoder;

    @Test
    public void bcrypt() {
        String encodedPwd = encoder.encode("12345");
        log.info("encodedPwd={}", encodedPwd);
    }
}
