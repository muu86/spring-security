package com.mj.securitystudy.filter;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Locale;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.util.StringUtils;

public class RequestValidationBeforeFilter implements Filter {

    public static final String AUTHENTICATION_SCHEME_BASIC = "Basic";

    private Charset credentialsCharset = StandardCharsets.UTF_8;

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse,
        FilterChain filterChain) throws IOException, ServletException {

        HttpServletRequest req = (HttpServletRequest) servletRequest;
        HttpServletResponse resp = (HttpServletResponse) servletResponse;
        String header = req.getHeader(AUTHORIZATION);
        if (header != null) {
            header = header.trim();
            if (StringUtils.startsWithIgnoreCase(header, AUTHENTICATION_SCHEME_BASIC)) {
                byte[] base64Token = header.substring(6).getBytes(StandardCharsets.UTF_8);
                byte[] decoded;
                try {
                    decoded = Base64.getDecoder().decode(base64Token);
                    String token = new String(decoded, getCredentialsCharset(req));
                    int delim = token.indexOf(":");
                    if (delim == -1) {
                        throw new BadCredentialsException("유효하지 않은 인증 토큰입니다.");
                    }
                    String email = token.substring(0, delim);
                    if (email.toLowerCase().contains("test")) {
                        resp.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                        return;
                    }
                } catch (IllegalArgumentException e) {
                    throw new BadCredentialsException("토큰 디코딩 실패");
                }
            }
        }
        filterChain.doFilter(servletRequest, servletResponse);
    }

    protected Charset getCredentialsCharset(HttpServletRequest request) {
        return getCredentialsCharset();
    }

    public Charset getCredentialsCharset() {
        return this.credentialsCharset;
    }
}
