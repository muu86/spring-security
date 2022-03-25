package com.mj.securitystudy.repository;

import com.mj.securitystudy.model.Customers;
import java.util.List;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface CustomerRepository extends CrudRepository<Customers, Long> {

    List<Customers> findByEmail(String email);

}
