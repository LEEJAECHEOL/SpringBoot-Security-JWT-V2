package com.example.jwt.config.auth;

public interface JwtProperties {
	String SECRET = "조익현"; // 우리 서버만 알고 있는 비밀값
	int EXPIRATION_TIME = (60000) * 10;  //(1분) * 10 = 10분
	String TOKEN_PREFIX = "Bearer ";
	String HEADER_STRING = "Authorization";
}
