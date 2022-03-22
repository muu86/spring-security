package com.mj.securitystudy.controller;

import java.util.Enumeration;
import javax.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ContactController {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    @GetMapping("/contact")
    public String saveContactInquiryDetails(String input) {
        return "문의 내용이 저장되었습니다";
    }

//    @GetMapping("/contact")
//    public String saveContactInquiryDetails(String input, HttpSession session) {
//        logger.info("session={}", session);
//        logger.info("session.JSESSIONID={}", session.getAttribute("JSESSIONID"));
//        Enumeration<String> attributeNames = session.getAttributeNames();
//        while (attributeNames.hasMoreElements()) {
//            logger.info("{}", attributeNames.nextElement());
//        }
//        return "문의 내용이 저장되었습니다.";
//    }

    @GetMapping("/contact-1")
    public String logUserDetails(String input, Authentication authentication) {
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        logger.info("userDetails.userName={}", userDetails.getUsername());
        return "문의 내용이 저장되었습니다.";
    }
}
