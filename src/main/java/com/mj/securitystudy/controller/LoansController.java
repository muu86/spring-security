package com.mj.securitystudy.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LoansController {
	
	@GetMapping("/my-loans")
	public String getLoanDetails(String input) {
		return "대출정보";
	}
}
