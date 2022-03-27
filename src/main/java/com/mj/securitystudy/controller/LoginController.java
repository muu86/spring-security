package com.mj.securitystudy.controller;

import com.mj.securitystudy.model.Customer;
import com.mj.securitystudy.repository.CustomerRepository;
import java.security.Principal;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@RestController
public class LoginController {

    private final CustomerRepository customerRepository;

    @GetMapping("/user")
    public Customer getUserDetailsAfterLogin(Principal user) {
        List<Customer> customers = customerRepository.findByEmail(user.getName());
        return (customers.size() > 0) ? customers.get(0) : null;
    }

}
