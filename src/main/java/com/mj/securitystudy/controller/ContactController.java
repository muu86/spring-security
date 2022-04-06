package com.mj.securitystudy.controller;

import com.mj.securitystudy.model.Contact;
import com.mj.securitystudy.repository.ContactRepository;
import java.sql.Date;
import java.util.List;
import java.util.Random;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreFilter;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@RestController
public class ContactController {

//    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    private final ContactRepository contactRepository;

    @PostMapping("/contact")
    @PreFilter("filterObject.contactName == 'Test'")
    public Contact saveContactInquiryDetails(@RequestBody Contact contact) {
        contact.setContactId(getServiceReqNumber());
        contact.setContactId(getServiceReqNumber());
        contact.setCreateDt(new Date(System.currentTimeMillis()));
        return contactRepository.save(contact);
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

    /*@GetMapping("/contact-1")
    public String logUserDetails(String input, Authentication authentication) {
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        logger.info("userDetails.userName={}", userDetails.getUsername());
        return "문의 내용이 저장되었습니다.";
    }*/

    private String getServiceReqNumber() {
        Random random = new Random();
        int ranNum = random.nextInt(999999999 - 9999) + 9999;
        return "SR" + ranNum;
    }
}
