package com.example.jwt.config.auth;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.example.jwt.domain.User;
import com.example.jwt.domain.UserRepository;

import lombok.RequiredArgsConstructor;

// http://localhost:8080/login 올때 동작

@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {
	
	private final UserRepository userRepository;
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		
		System.out.println("PrincipalDetailsService is Run");
		User userEntity = userRepository.findByUsername(username);
		
		return new PrincipalDetails(userEntity);
	}

}
