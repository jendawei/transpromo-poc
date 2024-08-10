package com.rawstone.transpromo.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
//import com.profetai.demo.jwt.filter.JwtAuthFilter;
//import com.profetai.demo.jwt.service.UserInfoService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.authentication.configurers.ldap.LdapAuthenticationProviderConfigurer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.config.ldap.LdapBindAuthenticationManagerFactory;
import org.springframework.security.config.ldap.LdapPasswordComparisonAuthenticationManagerFactory;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.LdapShaPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ldap.authentication.BindAuthenticator;
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider;
import org.springframework.security.ldap.authentication.PasswordComparisonAuthenticator;
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;
import org.springframework.security.ldap.userdetails.DefaultLdapAuthoritiesPopulator;
import org.springframework.security.ldap.userdetails.UserDetailsContextMapper;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.rawstone.transpromo.bean.CustomUserDetailsContextMapper;
import com.rawstone.transpromo.controller.DemoController;

import io.micrometer.common.util.StringUtils;

import static org.springframework.boot.autoconfigure.security.servlet.PathRequest.toH2Console;

import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {
	static Logger logger = LoggerFactory.getLogger(SecurityConfig.class);
	//
	/*
	@Value("${ldap.url:ldap://localhost:8389/dc=landon,dc=org}")
    private String ldapUrl;
	
	@Value("${ldap.user:}")
    private String ldapUser;
	
	@Value("${ldap.pass:}")
    private String ldapPass;
    */
	
	@Value("${ldap.searchBase:}")
	private String ldapSearchBase;
	
	@Value("${ldap.searhFilter:}")
	private String ldapSearhFilter;
	
	@Value("${ldap.userDnPatterns:}")
	private String ldapUserDnPatterns;
	
	@Value("${ldap.groupSearchBase:}")
	private String ldapGroupSearchBase;
	
	@Value("${ldap.groupSearchFilter:}")
	private String ldapGroupSearchFilter;
	
	@Autowired
	LdapContextSource ldapContextSource;

	@Autowired
    private DataSource dataSource;
	
	@Autowired
	CustomUserDetailsContextMapper userDetailsContextMapper;

    // Configuring HttpSecurity
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http
    		//, AuthenticationManager authManager
    		) throws Exception {
        return http.csrf(csrf -> csrf.disable()).headers(headers -> headers.frameOptions(frameOptions -> frameOptions.disable()))
        		.authorizeHttpRequests(auth -> auth.requestMatchers(AntPathRequestMatcher.antMatcher("/h2-console/**")).permitAll())
        	    .authorizeHttpRequests(auth -> auth.requestMatchers("/demo/**").permitAll())
                //.authorizeHttpRequests(auth -> auth.requestMatchers("/auth/welcome", "/auth/addNewUser", "/auth/generateToken").permitAll())
                //.authorizeHttpRequests(auth -> auth.requestMatchers("/auth/user/**").authenticated())
                //.authorizeHttpRequests(auth -> auth.requestMatchers("/auth/admin/**").authenticated())
                .sessionManagement(sess -> sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                //.authenticationManager(authManager)
                //.authenticationProvider(authenticationProvider())
                //.addFilterBefore(authFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }
    
    //this seems not work, it will cause error indicating the shared beanx(@Bean) still in creation.
    /*
    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
    	//authenticationManagerBuilder.authenticationProvider(customAuthProvider);
        addLdapAuthentication(auth);
        //addDaoAuthentication(auth);
    }*/
    
    //this seems not work well in Spring-security 6. The wrong user/pass will hang and finall cause stackoverflow errors. 
    /*
    @Bean
    public AuthenticationManager authManager(HttpSecurity http) throws Exception {
        AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
        
        //authenticationManagerBuilder.
        //authenticationManagerBuilder.authenticationProvider(customAuthProvider);
        //addLdapAuthentication(authenticationManagerBuilder);
        //addDaoAuthentication(authenticationManagerBuilder);
        
        //authenticationManagerBuilder.authenticationProvider(authenticationProvider());
        authenticationManagerBuilder.authenticationProvider(ldapAuthenticationProvider());
       
        return authenticationManagerBuilder.build();
    }*/
    
    //Observed from LdapPasswordComparisonAuthenticationManagerFactory. This works fine in Spring-security 6.
    @Bean
    public AuthenticationManager createAuthenticationManager(LdapAuthenticationProvider ldapAuthenticationProvider) {
		//LdapAuthenticationProvider ldapAuthenticationProvider = ldapAuthenticationProvider();
		DaoAuthenticationProvider daoAuthenticationProvider = daoAuthenticationProvider();
		return new ProviderManager(ldapAuthenticationProvider, daoAuthenticationProvider);
	}
      
   
    //this works in Spring-security 6
    @Bean
    
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(new JdbcUserDetailsManager(dataSource));
        provider.setPasswordEncoder(new BCryptPasswordEncoder());  // Use BCrypt password encoder
        return provider;
    }
    
    @Profile("ldap-auth-compare-pass")
    @Bean
    LdapAuthenticationProvider ldapAuthenticationProvider1(PasswordEncoder passwordEncoder) {
    	//BindAuthenticator bindAuthenticator = new BindAuthenticator(contextSource());
    	PasswordComparisonAuthenticator ldapAuthenticator = new PasswordComparisonAuthenticator(ldapContextSource);
    	
    	if (StringUtils.isNotBlank(ldapSearchBase) && StringUtils.isNotBlank(ldapSearhFilter)) {
    		ldapAuthenticator.setUserSearch(
				new FilterBasedLdapUserSearch(ldapSearchBase, ldapSearhFilter, ldapContextSource));
    	}
    	
    	ldapAuthenticator.setPasswordAttributeName("userPassword");
    	
    	if (StringUtils.isNotBlank(ldapUserDnPatterns)) {
    		ldapAuthenticator.setUserDnPatterns(new String[]{ldapUserDnPatterns});
    	}
    	
    	//ldapAuthenticator.setPasswordEncoder(new BCryptPasswordEncoder());
    	ldapAuthenticator.setPasswordEncoder(passwordEncoder);
           
        
    	DefaultLdapAuthoritiesPopulator authoritiesPopulator = null;
        if (StringUtils.isNotBlank(ldapGroupSearchBase)) {
        	authoritiesPopulator = new DefaultLdapAuthoritiesPopulator(ldapContextSource, ldapGroupSearchBase);
        	
        	if (StringUtils.isNotBlank(ldapGroupSearchFilter)) {
        		authoritiesPopulator.setGroupSearchFilter(ldapGroupSearchFilter);
        	}
        	//authoritiesPopulator.setGroupSearchFilter("(uniqueMember={0})");
        }
        
        LdapAuthenticationProvider ldapAuthenticationProvider = authoritiesPopulator == null ? 
        		new LdapAuthenticationProvider(ldapAuthenticator): new LdapAuthenticationProvider(ldapAuthenticator, authoritiesPopulator);
        
        ldapAuthenticationProvider.setUserDetailsContextMapper(userDetailsContextMapper);
        
        return ldapAuthenticationProvider;
    }
    
    
    @Profile("ldap-auth-bind")
    @Bean
    LdapAuthenticationProvider ldapAuthenticationManager2(BaseLdapPathContextSource contextSource) {
    	//
    	BindAuthenticator bindAuthenticator = new BindAuthenticator(ldapContextSource);
    	
    	if (StringUtils.isNotBlank(ldapUserDnPatterns)) {
    		bindAuthenticator.setUserDnPatterns(new String[]{ldapUserDnPatterns});
    	}
        
        if (StringUtils.isNotBlank(ldapSearchBase) && StringUtils.isNotBlank(ldapSearhFilter)) {
        	bindAuthenticator.setUserSearch(
				new FilterBasedLdapUserSearch(ldapSearchBase, ldapSearhFilter, ldapContextSource));
    	}
        
        DefaultLdapAuthoritiesPopulator authoritiesPopulator = null;
        if (StringUtils.isNotBlank(ldapGroupSearchBase)) {
        	authoritiesPopulator = new DefaultLdapAuthoritiesPopulator(ldapContextSource, ldapGroupSearchBase);
        	
        	if (StringUtils.isNotBlank(ldapGroupSearchFilter)) {
        		authoritiesPopulator.setGroupSearchFilter(ldapGroupSearchFilter);
        	}
        	//authoritiesPopulator.setGroupSearchFilter("(uniqueMember={0})");
        }
        
        LdapAuthenticationProvider ldapAuthenticationProvider = authoritiesPopulator == null ? 
        		new LdapAuthenticationProvider(bindAuthenticator): new LdapAuthenticationProvider(bindAuthenticator, authoritiesPopulator);
        //LdapAuthenticationProvider ldapAuthenticationProvider = new LdapAuthenticationProvider(bindAuthenticator);
        
        ldapAuthenticationProvider.setUserDetailsContextMapper(userDetailsContextMapper);
        
        return ldapAuthenticationProvider;
    }
    
    @Profile("ldap-auth-pass-sha")
    @Bean
    PasswordEncoder LdapShaPasswordEncoder() {
    	return new LdapShaPasswordEncoder();
    }
    
    @Profile("ldap-auth-pass-bcrypt")
    @Bean
    PasswordEncoder bcryptPasswordEncoder() {
    	return new BCryptPasswordEncoder();
    }
    
    //this doesn't work(or only partially work) in Spring-security 6
    /*
    private void addLdapAuthentication(AuthenticationManagerBuilder auth) throws Exception {
        auth.ldapAuthentication()
                .userDnPatterns("uid={0},ou=people")
                .groupSearchBase("ou=groups")
                //.userDetailsContextMapper(userDetailsContextMapper())
                .userDetailsContextMapper(userDetailsContextMapper)
                //.contextSource()
                .contextSource(contextSource())
                //.url("ldap://localhost:8389/dc=landon,dc=org")
                //.and()
                .passwordCompare()
                .passwordEncoder(new BCryptPasswordEncoder())
                .passwordAttribute("userPassword");
    }*/
    
    //this could work for "binding" type, like ctcb/open ldap...
    /*
    @Bean
    AuthenticationManager ldapAuthenticationManager(
            BaseLdapPathContextSource contextSource) {
        LdapBindAuthenticationManagerFactory factory = 
            new LdapBindAuthenticationManagerFactory(contextSource);
        factory.setUserDnPatterns("uid={0},ou=people");
        factory.setUserDetailsContextMapper(userDetailsContextMapper);
        return factory.createAuthenticationManager();
    }*/
    
    //this works for embedded ldap server
    /*
    @Bean
    AuthenticationManager ldapAuthenticationManager(
            BaseLdapPathContextSource contextSource) {
    	LdapPasswordComparisonAuthenticationManagerFactory  factory = 
            new LdapPasswordComparisonAuthenticationManagerFactory(contextSource, new BCryptPasswordEncoder());
        factory.setUserDnPatterns("uid={0},ou=people");
        factory.setUserDetailsContextMapper(userDetailsContextMapper);
        factory.setPasswordAttribute("userPassword");
        return factory.createAuthenticationManager();
    }

    //this doesn't work(or only partially work) in Spring-security 6
    /*
    private void addDaoAuthentication(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(new JdbcUserDetailsManager(dataSource))
    //userDetailsPasswordManager((UserDetailsPasswordService) new JdbcUserDetailsManager(dataSource))
                //.dataSource(dataSource)
                //.usersByUsernameQuery("select username, password, enabled from users where username=?")
                //.authoritiesByUsernameQuery("select username, authority from authorities where username=?")
                .passwordEncoder(new BCryptPasswordEncoder())
        ;
    }*/
  

}
