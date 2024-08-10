package com.rawstone.transpromo.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/demo")
public class DemoController {
	static Logger logger = LoggerFactory.getLogger(DemoController.class);
	//
	@Autowired
	AuthenticationManager authenticationManager;
	
	@RequestMapping("/")
	public String hello() {
		
		return "hello";
	}
	
	@RequestMapping("/testAuthentication")
	public Authentication testAuthentication(String uid, String pass) {
		logger.debug("testAuthentication>> uid: " + uid + ", pass: " + pass);
		
		Authentication authToken = null;
		
		try {
			Authentication authRequest = new UsernamePasswordAuthenticationToken(uid, pass);
			
			authToken = authenticationManager.authenticate(authRequest);
		} catch (Throwable exp) {
			//exp.printStackTrace();
			logger.debug("exception: " + exp.getMessage());
			authToken = new AnonymousAuthenticationToken(
				    "key", "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_NONE"));
		}
		
		
		logger.debug("<< authToken: " + (authToken == null? "Nothing": authToken));
		return authToken;
		//return "testAuthentication is done!";
	}

	
}
