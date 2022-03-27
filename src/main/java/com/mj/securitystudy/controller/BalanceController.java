package com.mj.securitystudy.controller;

import com.mj.securitystudy.model.AccountTransactions;
import com.mj.securitystudy.model.Customer;
import com.mj.securitystudy.repository.AccountTransactionsRepository;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@RestController
public class BalanceController {

    private final AccountTransactionsRepository accountTransactionsRepository;

    @PostMapping("/my-balance")
    public List<AccountTransactions> getBalanceDetails(@RequestBody Customer customer) {
        return accountTransactionsRepository
            .findByCustomerIdOrderByTransactionDtDesc(customer.getId());
    }
}
