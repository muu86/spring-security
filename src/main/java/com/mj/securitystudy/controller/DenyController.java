package com.mj.securitystudy.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DenyController {

    @GetMapping("/deny")
    public String deny(String input) {
        return "deny all";
    }
}
