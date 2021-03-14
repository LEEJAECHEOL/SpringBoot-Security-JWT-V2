package com.example.jwt.config.jwt;

import java.io.IOException;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.jwt.config.auth.JwtProperties;
import com.example.jwt.config.auth.PrincipalDetails;
import com.example.jwt.domain.User;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.RequiredArgsConstructor;


// 스프링 시큐리티에서 UsernamePasswordAuthenticationFilter가 있음
// /login 요청해서 username, password 전송하면 (post)
// UsernamePasswordAuthenticationFilter 가 동작

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
	
	private final AuthenticationManager authenticationManager;
	
	// /login 요청을 하면 로그인 시도를 위해서 실행되는 함수. 
	
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		System.out.println("JwtAuthenticationFilter : 로그인 시도중");
		
		// 1. username, password를 받아서
		try {
//			// 원시적인 방법 자바에서 기본임.
//			BufferedReader br = request.getReader();
//			String input = null;
//			while((input = br.readLine()) != null) {
//				System.out.println(input);
//				// 요기서 파싱해야댐.
//			}
			ObjectMapper om = new ObjectMapper();
			User user = om.readValue(request.getInputStream(), User.class);
			System.out.println(user);
			
			// 유저네임패스워드 토큰 생성
			UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
			
			// 2. 정상인지 로그인 시도를 해야함. authenticationManager로 로그인 시도를 하면 
			//    PrincipalDetailsService가 호출됨.(loadUserByUsername()함수 실행됨.)
			
			// PrincipalDetailsService의 loadUserByUsername()함수가 실행된 후 정상이면 authentication이 리턴
			// authentication에 내 로그인한 정보가 담김
			// 데이터베이스에 있는 username과 password가 일치한다.
			Authentication authentication = authenticationManager.authenticate(authenticationToken);


			// 3. PrincipalDetails를 세션에 담고 (권한 관리를 위해서)
			//  = 로그인이 되었다는 뜻.
			PrincipalDetails principalDetails = (PrincipalDetails)authentication.getPrincipal();
			System.out.println("로그인 완료됨 ? : " + principalDetails.getUser().getUsername()); // 로그인이 정상적으로 되었다는 뜻
			
			// authentication 객체가 session영역에 저장해야 하 그 방법이 return 해주면 됨.
			// 리턴 이유는 권한 관리를 security가 대신 해주기 때문에 편하려고 하는것
			// 굳이 JWT토큰을 사용하면서 세션을 만들 이유가 없음. 근데 단지 권한 처리때문에 session에 넣어줌.
			
			
			return authentication; 
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
		return null;
	}
	
	// attemptAuthentication 실행 후 인증이 정상적으로 되었으면 successfulAuthentication함수가 실행됨.
	// JWT토큰을 만들어서 request 요청한 사용자에게 JWT토큰을 response해주면 됨.
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		// 4. JWT토큰을 만들어서 응답해주면 됨.
		System.out.println("successfulAuthentication 실행됨 : 인증 완료");
		
		PrincipalDetails principalDetails = (PrincipalDetails)authResult.getPrincipal();
		
		// Hash암호 방식
		String jwtToken = JWT.create()
				.withSubject("cosToken")
				.withExpiresAt(new Date(System.currentTimeMillis() + JwtProperties.EXPIRATION_TIME)) // 만료 시간
				.withClaim("id", principalDetails.getUser().getId()) // 내가 넣고 싶은 key:value
				.withClaim("username", principalDetails.getUser().getUsername())
				.sign(Algorithm.HMAC512(JwtProperties.SECRET));
		
		response.addHeader(JwtProperties.HEADER_STRING, JwtProperties.TOKEN_PREFIX + jwtToken);
	}
	
	/**
	 * 
	 * ===== 세션 쿠키 방식
	 * 유저 네임, 패스워드 로그인 정상
	 * 
	 * 서버 쪽 세션 ID생성클라이언트 쿠키 세션 ID를 응답
	 * 
	 * 요청할 때 마다 쿠키값 세션Id를 항상 들고 서버쪽으로 요청하기 때문에
	 * 서버는 세션ID가 유효한지 판단해서 유효하면 인증이 필요한 페이지로
	 * 접근하게 하면 됨.
	 * 
	 * 
	 * ====== JWT 토큰 방식
	 * 
	 * 유저 네임, 패스워드 로그인 정상
	 * JWT 토큰을 생성
	 * 클라이언트 쪽으로 JWT 토을 응답
	 * 요청할 때마다 JWT 토큰을 가지고 요청
	 * 서버는 JWT 토큰이 유효한지를 판단을 해야함
	 * 
	 */
}
