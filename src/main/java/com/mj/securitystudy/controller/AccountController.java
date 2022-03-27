package com.mj.securitystudy.controller;

import com.mj.securitystudy.repository.AccountsRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@RestController
public class AccountController {

    private final AccountsRepository accountsRepository;

    @GetMapping("/my-account")
    public String getAccountDetails(String input) {
        return "내 정보";
    }
}
