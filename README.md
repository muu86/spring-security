## 스프링 시큐리티
<img width="716" alt="스크린샷 2022-03-30 오후 10 14 52" src="https://user-images.githubusercontent.com/71859468/160843096-e976c156-6f1a-4906-86e1-228cc63b79ab.png">

### User인터페이스 이해

1. UserDetails  
   - 유저 정보를 저장하는 인터페이스
   - 인터페이스를 구현해서 확장가능(email 주소 등)
   - spring-security Reference => User 클래스
   - User 클래스는 UserBuilder 도 포함하고 있음
2. UserDetailsService  
   - DB에서 유저 정보를 가져옴
   - loadUserByUsername()
3. UserDetailsManager  
    - UserDetailsService 인터페이스를 상속하여 확장한 인터페이스  
      - createUser
      - updateUser
      - deleteUser
      - changePassword
      - userExists
    - 구현 클래스
      - InMemoryUserDetailsManager
      - JdbcUserDetailsManager
 
4. JdbcUserDetailsManager  
   - UserDetailsManager 의 구현체 중 하나
   - loadUserByUsername() 메소드는 JdbcDaoImpl에서 상속받음
   ```java
   public class JdbcDaoImpl extends JdbcDaoSupport implements UserDetailsService, MessageSourceAware {  
       public static final String DEF_USERS_BY_USERNAME_QUERY = "select username,password,enabled "
                                                            + "from users "
                                                            + "where username = ?";
   }
   ```
   - sql 문이 하드코딩되어 있으므로 `username`, `user` 와 같은 컬럼명, 테이블명이 내 db 컬럼명, 테이블명과 일치해야 한다.  

### JPA 적용
Customer Entity  
~~~java
@Getter
@Setter
@Entity
public class Customer {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private int id;
    private String email;
    private String pwd;
    private String role;

}
~~~
email => username  
pwd   => password  
UserDetailsService의 findByUser 메소드는 테이블명, 컬럼명이 고정되어 있음.  
내 클래스에 맞춰서 사용하고 싶으면 내 클래스를 멤버로 가지고 있는 래퍼 클래스를 만들 수 있다.  
래퍼 클래스가 UserDetails 나 UserDetailsService 를 구현하고  
이를 통해서 스프링 시큐리티가 제공하는 메소드 호출.
~~~java
@RequiredArgsConstructor
public class SecurityCustomer implements UserDetails {

    @Serial
    private static final long serialVersionUID = 1L;

    private final Customer customer;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        List<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority(customer.getRole()));
        return authorities;
    }

    @Override
    public String getPassword() {
        return customer.getPwd();
    }

    @Override
    public String getUsername() {
        return customer.getEmail();
    }

    //...

}
~~~
jpa CrudRepository 상속받은 CustomerRepository 는 findByEmail 메소드로 유저를 가져오고  
spring-security UserDetailsService 는 loadByUsername 으로 유저를 가져온다.
MjBankUserDetailsService 둘을 연결하는 어댑터 클래스.
~~~java
@RequiredArgsConstructor
@Service
public class MjBankUserDetailsService implements UserDetailsService {

    private final CustomerRepository customerRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        List<Customer> customer = customerRepository.findByEmail(username);
        if (customer.size() == 0) {
            throw new UsernameNotFoundException("UserDetails not found for the user : " + username);
        }
        return new SecurityCustomer(customer.get(0));
    }
}
~~~
_MjBankUserDetailsService 클래스에서 경고 -> class can be record_  
_jdk14 부터 record 클래스가 추가되었음. 자세한 내용 확인해볼 것_  

### PasswordEncoder
스프링 시큐리티는 PasswordEncoder Interface 와 다음의 구현 클래스를 제공  
   - NoOpPasswordEncoder: 암호화하지 않음. 테스트용으로 사용한다.  
   - StandardPasswordEncoder: 다이제스트 + 솔트 (sha-256) 방식.  스프링 시큐리티가 더이상 권장하지 않음.  
   - Pbkdf2PasswordEncoder: 다이제스트 + 솔트 방식에 반복횟수를 지정할 수 있음.
   - BcryptPasswordEncoder: 해쉬함수가 의도적으로 느리게 만들어졌음. 스프링 시큐리티가 권장하고 시간을 1초로 튜닝 권함.
   - ScryptPasswordEncoder: 하드웨어 사용량을 입력으로 넣어서 더 느리게.

### Authentication Provider, Manager
AuthenticationProvicer: UserDetails 와 PasswordEncoder를 이용하여 유저 인증 여부를 결정하는 컴포넌트.  
username, password 외 다른 custom 인증방법이 필요한 경우 AuthenticationProvider를 직접 구현하여 추가할 수 있다.  
구현체 => DaoAuthenticationProvider: UserDetailsService를 이용해서 유저를 인증.  

AuthenticationManager: Provider List를 가지고 supports 메소드가 true를 리턴한 Provider의 authenticate 메서드를 호출함.  
구현체 => ProviderManager  
```java
public interface AuthenticationProvider {
    
	Authentication authenticate(Authentication authentication) throws AuthenticationException;

	boolean supports(Class<?> authentication);

}
```
```java
public class ProviderManager implements AuthenticationManager, MessageSourceAware, InitializingBean {
    // ...
    private List<AuthenticationProvider> providers = Collections.emptyList();
    // ...
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
       // ..
       for (AuthenticationProvider provider : getProviders()) {
          if (!provider.supports(toTest)) {
             continue;
          }
          if (logger.isTraceEnabled()) {
             logger.trace(LogMessage.format("Authenticating request with %s (%d/%d)",
                     provider.getClass().getSimpleName(), ++currentPosition, size));
          }
          try {
             result = provider.authenticate(authentication);
             if (result != null) {
                copyDetails(authentication, result);
                break;
             }
          }
          catch (AccountStatusException | InternalAuthenticationServiceException ex) {
             prepareException(ex, authentication);
             // SEC-546: Avoid polling additional providers if auth failure is due to
             // invalid account status
             throw ex;
          }
          catch (AuthenticationException ex) {
             lastException = ex;
          }
       }
       //..
    }
}
```

### Authentication 인터페이스
org.springframework.security.core.Authentication
java.security.Principal  
Authentication 인터페이스는 자바 표준 라이브러리의 Principal 을 상속하여 확장함


Principal은 하나의 메소드를 가짐: getName()  
Authentication 은 여기에 isAuthenticated(), getAuthorites() 등 유저 인증에 관한 메서드를 추가  


#### AbstractUserDetailsAuthenticationProvider
DaoAuthenticationProvider 가 상속 받는 클래스로 authenticate 메서드를 가지고 있다.  
```java
public abstract class AbstractUserDetailsAuthenticationProvider
		implements AuthenticationProvider, InitializingBean, MessageSourceAware {

   @Override
   public Authentication authenticate(Authentication authentication)
           throws AuthenticationException {
      // ...
      return createSuccessAuthentication(principalToReturn, authentication, user);
   }
   
   protected Authentication createSuccessAuthentication(Object principal,
           Authentication authentication,
           UserDetails user) {
      UsernamePasswordAuthenticationToken result = new UsernamePasswordAuthenticationToken(
              principal,
              authentication.getCredentials(),
              this.authoritiesMapper.mapAuthorities(user.getAuthorities()));
      result.setDetails(authentication.getDetails());
      this.logger.debug("Authenticated user");
      return result;
   }
}
```


직접 구현한 **AuthenticationProvider**  
```java
@Component
public class MjBankUsernamePwdAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private CustomerRepository customerRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication)
        throws AuthenticationException {

        String username = authentication.getName();
        String pwd = authentication.getCredentials().toString();
        List<Customers> customers = customerRepository.findByEmail(username);
        if (customers.size() > 0) {
            if (passwordEncoder.matches(pwd, customers.get(0).getPwd())) {
                List<GrantedAuthority> authorities = new ArrayList<>();
                authorities.add(new SimpleGrantedAuthority(customers.get(0).getRole()));
                return new UsernamePasswordAuthenticationToken(username, pwd, authorities);
            } else {
                throw new BadCredentialsException("비밀번호가 틀렸음...");
            }
        } else {
            throw new BadCredentialsException("없는 유저임.");
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
}
```

### CSRF 이슈 (Cross Site Request Forgery)
사용자가 피해사이트에 로그인한 상태로 세션데이터를 가지고 있고 해커가 악용사이트에서 이 세션 정보를 이용하여 피해사이트로 위조된  
요청을 하는 것  
보호 방법: 피해사이트에서 CSRF 토큰을 발행하고 이 토큰을 가지고 있는 요청만 정당한 요청으로 판단함으로써 CSRF 를 예방할 수 있다.  
```java
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

   /*
   /my-account - secured
   /my-balance - secured
   /my-loans   - secured
   /my-cards   - secured

   /notices    - not secured
   /contact    - not secured
    */
   @Override
   protected void configure(HttpSecurity http) throws Exception {
      http
              .cors().configurationSource(request -> {
                 CorsConfiguration config = new CorsConfiguration();
                 config.setAllowedOrigins(Collections.singletonList("http://localhost:4200"));
                 config.setAllowedMethods(Collections.singletonList("*"));
                 config.setAllowCredentials(true);
                 config.setAllowedHeaders(Collections.singletonList("*"));
                 config.setMaxAge(3600L);
                 return config;
              })
              .and()
              .csrf().ignoringAntMatchers("/contact")
              .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
              .and()
              //...
              .httpBasic();
   }
}
```
spring security **CsrfConfigurer** 에 **CsrfTokenRepository**(인터페이스)를 멤버로 세팅함.  
**CsrfTokenRepository** 의 구현체는 **CookieCsrfTokenRepository**  
```java
public final class CookieCsrfTokenRepository implements CsrfTokenRepository {

   static final String DEFAULT_CSRF_COOKIE_NAME = "XSRF-TOKEN";

   static final String DEFAULT_CSRF_PARAMETER_NAME = "_csrf";

   static final String DEFAULT_CSRF_HEADER_NAME = "X-XSRF-TOKEN";
}
```
   - 클라이언트가 GET 요청을 보냈을 때 서버는 Set-cookie 헤더로 생성된 XSRF-TOKEN을 보냄
   - 브라우저가 쿠키에 토큰을 set
   - POST 요청을 할 때 브라우저는 request 헤더에 토큰을 담고
   - 브라우저가 헤더와 쿠키를 함께 서버로 전달
   - 서버는 쿠키의 토큰 정보와 헤더의 토큰 정보를 비교하여 요청을 승인/거부
   - **CookieCsrfTokenRepository**의 withHttpOnlyFalse 메서드는 Angular 등의 js 코드가 쿠키정보를 읽을 수 있도록 허용한다.
   - csrf 적용을 원하지 않는 경로는 **ignoringAntMatchers**메서드로 해결가능

### Authentication(인증) VS Authorization(권한)
```java
public interface UserDetails extends Serializable {
   Collection<? extends GrantedAuthority> getAuthorities();
}
```
```java
public interface GrantedAuthority extends Serializable {
	String getAuthority();
}
```

#### Authorities VS Role
권한과 역할  
역할은 권한들의 집합일 수 있다.  
spring-security 에서 Role 은 'ROLE_' 접두사로 시작해야 한다.  


### MvcMatchers VS antMatchers
비슷하지만 mvcMatcher를 사용하는 것이 더 안전하다.  
antMatchers("/secured") 는 /secured 경로만 매치되는 반면,
mvcMatchers("/secured") 는 /secured/, /secured.html 등에도 매칭됨  

### Filter 구현하기
#### 스프링 시큐리티 필터
```java
 private static final class VirtualFilterChain implements FilterChain {

     private final List<Filter> additionalFilters;

     private final int size;

     private int currentPosition = 0;

     @Override
     public void doFilter(ServletRequest request, ServletResponse response) throws IOException, ServletException {
         if (this.currentPosition == this.size) {
             if (logger.isDebugEnabled()) {
                 logger.debug(LogMessage.of(() -> "Secured " + requestLine(this.firewalledRequest)));
             }
             // Deactivate path stripping as we exit the security filter chain
             this.firewalledRequest.reset();
             this.originalChain.doFilter(request, response);
             return;
         }
         this.currentPosition++;
         Filter nextFilter = this.additionalFilters.get(this.currentPosition - 1);
         if (logger.isTraceEnabled()) {
             logger.trace(LogMessage.format("Invoking %s (%d/%d)", nextFilter.getClass().getSimpleName(),
                     this.currentPosition, this.size));
         }
         nextFilter.doFilter(request, response, this);
     }

 }
```
additionalFilters 에 담긴 Filter의 doFilter 메서드를 하나씩 호출하는 방식으로 구현되어 있음.  

#### addFilterBefore
security 설정파일에서 **addFilterBefore** 메서드를 이용하여 custom Filter를 삽입하는 것이 가능.  
```java
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
```
```java
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

   @Override
   protected void configure(HttpSecurity http) throws Exception {
      http
              // ...
              .addFilterBefore(new RequestValidationBeforeFilter(), BasicAuthenticationFilter.class)
              // ...
   }
}
```

#### addFilterAfter
```java
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
```

#### addFilterAt(filterA, filterB.class)
필터B 위치에 필터A 삽입. 필터B를 대체하지 않음. 둘의 chain 순서는 랜덤이다.  
```java
@Slf4j
public class AuthoritiesLoggingAtFilter implements Filter {

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse,
        FilterChain filterChain) throws IOException, ServletException {

        log.info("인증 진행 중..");
        filterChain.doFilter(servletRequest, servletResponse);
    }
}
```

#### GenericFilterBean, OncePerRequestFilter
GenericFilterBean: custom Filter를 구현하는데 도움이 될 수 있는 시큐리티 제공 추상 클래스  
OncePerRequestFilter: 스프링시큐리티는 리퀘스트 한번에 필터 한번이 실행되는 것을 보장하지 않는다. 이를 보장하는 클래스.  
BasicAuthenticationFilter 가 OncePerRequestFilter를 상속함!  

#### JWT(Json Web Token)
3 파트로 나뉨.  
**Header.Payload.Signature(Optional)**  
유저 인증에 사용. 뿐만 아니라 유저 관련 데이터도 서버로 전송가능(header, payload). 세션에 데이터를 보관하는 부담을 덜 수 있음.  
> Header: 해쉬알고리즘, 타입(jwt)

> Payload 파트 : 유저 관련 정보. ex) name, role...

> Signature 파트 : JWT는 Header와 Payload 를 담는 json 포맷을 base64로 인코딩한 것 -> 쉽게 위변조가 가능하다.  
Signature 파트는 Header와 Payload를 secret를 묶어 Header에 명시된 해쉬함수로 암호화한 것.  
해쉬함수(header + '.' + payload, secret)  

JWT 사용   
=> CSRF 토큰, spring-security 기본 발행 토큰(JSESSIONID) 필요없다.  
JWT 자체로 현재 요청이 정당한 유저에 의한 요청임을 증명하기 때문.  
```java
   http
      .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
        ...
      .csrf().disable()
       /*
      .ignoringAntMatchers("/contact")
      .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
       */
```
jjwt 라이브러리 사용  
서버에서 사용자 첫 인증 시 jwt 토큰 발급
```java
// 로그인 시 jwt 토큰을 한번만 발행
public class JwtTokenGeneratorFilter extends OncePerRequestFilter {

   @Override
   protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
           FilterChain filterChain) throws ServletException, IOException {

      Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
      if (null != authentication) {
         SecretKey key = Keys.hmacShaKeyFor(
                 SecurityConstants.JWT_KEY.getBytes(StandardCharsets.UTF_8)); // 서버가 특정한 키
         String jwt = Jwts.builder().setIssuer("mj bank").setSubject("JWT Token")
                 .claim("username", authentication.getName())
                 .claim("authorities", populateAuthorities(authentication.getAuthorities()))
                 .setIssuedAt(new Date())
                 .setExpiration(new Date(new Date().getTime() + 30000))
                 .signWith(key).compact();// 헤더, 페이로드를 키로 암호화

         response.setHeader(SecurityConstants.JWT_HEADER, jwt); // response header 에 token 전송
      }

      filterChain.doFilter(request, response);
   }

   @Override
   protected boolean shouldNotFilter(HttpServletRequest request) {
      // `/user` 로 들어온 요청에만 이 필터를 적용
      return !request.getServletPath().equals("/user");
   }


   private String populateAuthorities(Collection<? extends GrantedAuthority> collection) {
      Set<String> authoritiesSet = new HashSet<>();

      for (GrantedAuthority authority : collection) {
         authoritiesSet.add(authority.getAuthority());
      }

      return String.join(",", authoritiesSet);
   }
}
```

사용자가 요청마다 토큰을 헤더에 담아 보내고 서버는 매 요청마다 검증
```java
public class JWTTokenValidatorFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
        FilterChain filterChain) throws ServletException, IOException {

        String jwt = request.getHeader(SecurityConstants.JWT_HEADER);
        if (null != jwt) {
            try {
                SecretKey secretKey = Keys.hmacShaKeyFor(
                    SecurityConstants.JWT_KEY.getBytes(StandardCharsets.UTF_8));

                Claims claims = Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(jwt)    // request header로 전송된 jwt를 parse
                    .getBody();
                String username = claims.get("username", String.class);
                String authorities = claims.get("authorities", String.class);
                Authentication auth = new UsernamePasswordAuthenticationToken(
                    username, null,
                    AuthorityUtils.commaSeparatedStringToAuthorityList(authorities));
                SecurityContextHolder.getContext().setAuthentication(auth);
            } catch (Exception e) {
                throw new BadCredentialsException("Invalid Token received");
            }
        }

        filterChain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return request.getServletPath().equals("/user");
    }
}
```