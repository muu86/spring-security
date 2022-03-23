## 스프링 시큐리티

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
    - UserDetailsService 인터페이스를 상속하여 확장
    - createUser, updateUser .. 등 추가
    - InMemoryUserDetailsManager, JdbcUserDetailsManager
 
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
spring-security 의 UserDetailsService 로 Customer 엔티티를 관리하기 위해 래퍼 클래스에서 UserDetals를 구현
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
jpa CrudRepository 상속받은 CustomerRepository 는 findByEmail 메소드로 유저를 가져옴  
MjBankUserDetailsService 클래스로 CustomerRepository 를 래핑  
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
