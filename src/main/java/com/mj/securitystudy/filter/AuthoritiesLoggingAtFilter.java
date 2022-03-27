package com.mj.securitystudy.filter;

import java.io.IOException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class AuthoritiesLoggingAtFilter implements Filter {

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse,
        FilterChain filterChain) throws IOException, ServletException {

        log.info("인증 진행 중..");
        filterChain.doFilter(servletRequest, servletResponse);
    }
}
