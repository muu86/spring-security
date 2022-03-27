package com.mj.securitystudy.filter;

import java.io.IOException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

@Slf4j
public class AuthoritiesLoggingAfterFilter implements Filter {

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse,
        FilterChain filterChain) throws IOException, ServletException {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (null != authentication) {
            log.info("인증 성공! [{}] / 권한 [{}]", authentication.getName(),
                authentication.getAuthorities().toString());
        }

        filterChain.doFilter(servletRequest, servletResponse);
    }
}
