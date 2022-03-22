package com.mj.securitystudy.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CardsController {
	
	@GetMapping("/my-cards")
	public String getCardDetails(String input) {
		return "카드 정보";
	}

}
