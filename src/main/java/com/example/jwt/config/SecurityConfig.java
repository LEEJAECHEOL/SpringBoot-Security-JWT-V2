package com.example.jwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;

import com.example.jwt.config.jwt.JwtAuthenticationFilter;
import com.example.jwt.config.jwt.JwtAuthorizationFilter;
import com.example.jwt.domain.UserRepository;
import com.example.jwt.filter.MyFilter3;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity  // 이 configsecurity를 활성화
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	
	private final CorsConfig corsConfig;
	private final UserRepository userRepository;
	
    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
//		// 그냥 addfilter를 사용하면 에러가 발생
//		// 니필터는 스프링시큐리티필터체인에 등록이 안된다. 니필터는 타입이 필터이기 때문. 
//		// 굳이 걸고 싶으면 addFilterBefore, addFilterAfter를 사용해라
//		// 내시큐리티 필터가 시작되기 전에 걸든 후에 걸어라는 뜻.
//		http.addFilterAfter(new MyFilter1(), BasicAuthenticationFilter.class);
		http.addFilterBefore(new MyFilter3(), SecurityContextPersistenceFilter.class); // SecurityContextPersistenceFilter가 제일 먼저 시작됨. 즉 시큐리티가 동작하기 전에 작동함.
		http.csrf().disable();
		http
				// Bearer Auth(STATELESS)를 사용하겠다고 시큐리티에 알려줘야함.
				.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // STATELESS: session을 사용하지 않겠다는 의
				
			.and()
				.addFilter(corsConfig.corsFilter()) // @CrossOrigin(인증X), 시큐리티 필터에 등록 인증(O)
				.formLogin().disable()
				.httpBasic().disable()
				.addFilter(new JwtAuthenticationFilter(authenticationManager())) // AuthenticationManager
				.addFilter(new JwtAuthorizationFilter(authenticationManager(), userRepository))
				.authorizeRequests()
				.antMatchers("/api/v1/user/**")
					.access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
				.antMatchers("/api/v1/manager/**")
					.access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
				.antMatchers("/api/v1/admin/**")
					.access("hasRole('ROLE_ADMIN')")
				.anyRequest().permitAll()
				
		;
	}
}
