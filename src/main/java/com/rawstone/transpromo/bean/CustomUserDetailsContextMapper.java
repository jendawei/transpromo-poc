package com.rawstone.transpromo.bean;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;

import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.ldap.userdetails.LdapUserDetailsImpl;
import org.springframework.security.ldap.userdetails.LdapUserDetailsMapper;
import org.springframework.security.ldap.userdetails.UserDetailsContextMapper;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;

import com.rawstone.transpromo.model.UserPrincipal;

import org.slf4j.Logger; 
import org.slf4j.LoggerFactory; 

@Component
public class CustomUserDetailsContextMapper extends LdapUserDetailsMapper

//implements UserDetailsContextMapper 
{

	static Logger logger = LoggerFactory.getLogger(CustomUserDetailsContextMapper.class); 
	
	//In CTCB ldap, the roles(group membership) is defined as the attribute "groupMemberShip" in user-node.
	static String[] ctcb_role_attributes = {"groupMemberShip"}; 
	
	@Override
	public UserDetails mapUserFromContext(DirContextOperations ctx, String username,
			Collection<? extends GrantedAuthority> authorities) {
		logger.debug(">>");
		logger.debug("username: " + username);
		logger.debug("authorities(input): " + authorities);
		
		//Use objectClass to demonstrate how parent class resolve additional authorities.
		//this.setRoleAttributes(ctcb_role_attributes);		
		this.setRoleAttributes(new String[] {"objectClass"});
		
        LdapUserDetailsImpl details = (LdapUserDetailsImpl) super.mapUserFromContext(
        		ctx, username, authorities);
        
        Collection<GrantedAuthority> mergedAuthorities = details.getAuthorities();
        logger.debug("authorities(resolved by parent-class): " + mergedAuthorities);
		
		String dn = ctx.getDn().toString();
        logger.debug("dn: " + dn);
        
        UserPrincipal user = new UserPrincipal();
		
		List<GrantedAuthority> intrestedAuthorities = resolveIntrestedAuthorities(dn, mergedAuthorities);
		
        logger.debug("intrestedAuthorities: " + intrestedAuthorities);
        
        listNodeAttributes(ctx);
        
        try {
            //userCN = String.valueOf(ctx.getAttributes().get("cn").get());
            //userSN = String.valueOf(ctx.getAttributes().get("sn").get());
        }
        catch (Exception ex) {
            // TODO: Handle the exception!
        }

        user.setUserName(username);
		//user.setAuthorities(authorities);
		user.setAuthorities(intrestedAuthorities);
		user.setDn(dn);
		
		return user;
		
	}
	
	public UserDetails mapUserFromContext_old(DirContextOperations ctx, String username,
			Collection<? extends GrantedAuthority> authorities) {
		//System.out.println(">>username: " + username);
		//System.out.println("authorities: " + authorities);
		String dn = ctx.getDn().toString();
	
		logger.debug(">>");
		logger.debug("dn: " + dn);
		logger.debug("username: " + username);
		logger.debug("authorities: " + authorities);
		
		for (GrantedAuthority grantedAuthority: authorities) {
			logger.debug("--class: " + grantedAuthority.getClass() + 
					", authority: " + grantedAuthority.getAuthority());
		}
		
		UserPrincipal user = new UserPrincipal();
		
		/*
		//SimpleGrantedAuthority
		ArrayList<? extends GrantedAuthority> authorities_converted = new ArrayList<>();
		((List<GrantedAuthority>)authorities_converted).add(new SimpleGrantedAuthority("ROLE_USER"));
		*/
		
		List<GrantedAuthority> intrestedAuthorities = resolveIntrestedAuthorities(dn, null);
		
        logger.debug("intrestedAuthorities: " + intrestedAuthorities);
        
        listNodeAttributes(ctx);
       
		user.setUserName(username);
		//user.setAuthorities(authorities);
		user.setAuthorities(intrestedAuthorities);
		user.setDn(dn);
		
		return user;
	}

	@Override
	public void mapUserToContext(UserDetails user, DirContextAdapter ctx) {
		//
		throw new UnsupportedOperationException("Not implemented");
	}

	private List<GrantedAuthority> resolveIntrestedAuthorities(String dn, Collection<GrantedAuthority> authorities) {
		//demo!
		ArrayList<GrantedAuthority> intrestedAuthorities = new ArrayList<>();
		if (!CollectionUtils.isEmpty(authorities)) {
			intrestedAuthorities.addAll(authorities);
		}
		
		//intrestedAuthorities.add(new SimpleGrantedAuthority("ROLE_USER"));
		
		return intrestedAuthorities;
	}
	
	private void listNodeAttributes(DirContextOperations ctx) {
		// Get the multi-valued attribute from LDAP
		Attributes attributes = ctx.getAttributes();
		logger.debug("------------------------------------------------");
		try {
			for (NamingEnumeration<?> ae = attributes.getAll(); ae.hasMore();) {
			    Attribute attribute = (Attribute) ae.next();
			    logger.debug("processing attribute: " + attribute.getID());
			    
			    /* print each value */
			    for (NamingEnumeration<?> e = attribute.getAll(); e.hasMore(); ) {
			    		logger.debug("--value: " + e.next());
			    }
			}
		} catch (NamingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		logger.debug("------------------------------------------------");
	}
}
