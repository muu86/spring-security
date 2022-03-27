package com.mj.securitystudy.controller;

import com.mj.securitystudy.model.Accounts;
import com.mj.securitystudy.model.Customer;
import com.mj.securitystudy.repository.AccountsRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@RestController
public class AccountController {

    private final AccountsRepository accountsRepository;

    @PostMapping("/my-account")
    public Accounts getAccountDetails(@RequestBody Customer customer) {
        return accountsRepository.findByCustomerId(customer.getId());
    }
}
