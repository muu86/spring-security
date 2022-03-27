package com.mj.securitystudy.controller;

import com.mj.securitystudy.model.Customer;
import com.mj.securitystudy.model.Loans;
import com.mj.securitystudy.repository.LoanRepository;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@RestController
public class LoansController {

	private final LoanRepository loanRepository;
	
	@PostMapping("/my-loans")
	public List<Loans> getLoanDetails(@RequestBody Customer customer) {
		List<Loans> loans = loanRepository.findByCustomerIdOrderByStartDtDesc(customer.getId());
		return loans;
	}
}
