package com.mj.securitystudy.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class BalanceController {

    @GetMapping("/my-balance")
    public String getBalanceDetails(String input) {
        return "계좌 정보";
    }
}
