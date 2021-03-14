package com.example.jwt.filter;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class MyFilter3 implements Filter {

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		
		HttpServletRequest req = (HttpServletRequest)request;
		HttpServletResponse resp = (HttpServletResponse)response;
		resp.setCharacterEncoding("utf-8");
		
		// 토큰 : cos라고 가정  id, pw정상적으로 들어와서 로그인이 완료되면 토큰을 만들어 주고 그걸 응답해줌
		// 요청할 때마다 header에 Authrization에 value값으로 토큰을 가지고 옴
		// 그때 토큰이 넘어오면 이 토큰이 내가 만든 토큰이 맞는지만 검증 하면 됨. (RSA, HS256)
//		if(req.getMethod().equals("POST")) {
//			System.out.println("POST Request");
//			String headAuth = req.getHeader("Authorization");
//			System.out.println(headAuth);
//			System.out.println("필터3");
//			
//			if(headAuth.equals("cos")) {
//				chain.doFilter(request, response);
//			}else {
//				PrintWriter out = resp.getWriter();
//				out.print("인증안됨");
//				out.flush();
//			}
//		}

		chain.doFilter(request, response);
		
	}

}
