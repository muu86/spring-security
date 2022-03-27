package com.mj.securitystudy.controller;

import com.mj.securitystudy.model.Cards;
import com.mj.securitystudy.model.Customer;
import com.mj.securitystudy.repository.CardsRepository;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@RestController
public class CardsController {

	private final CardsRepository cardsRepository;
	
	@PostMapping("/my-cards")
	public List<Cards> getCardDetails(@RequestBody Customer customer) {
		List<Cards> cards = cardsRepository.findByCustomerId(customer.getId());
		return cards;
	}
}
