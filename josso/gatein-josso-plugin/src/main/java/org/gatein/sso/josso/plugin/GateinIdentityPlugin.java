/******************************************************************************
 * JBoss, a division of Red Hat                                               *
 * Copyright 2006, Red Hat Middleware, LLC, and individual                    *
 * contributors as indicated by the @authors tag. See the                     *
 * copyright.txt in the distribution for a full listing of                    *
 * individual contributors.                                                   *
 *                                                                            *
 * This is free software; you can redistribute it and/or modify it            *
 * under the terms of the GNU Lesser General Public License as                *
 * published by the Free Software Foundation; either version 2.1 of           *
 * the License, or (at your option) any later version.                        *
 *                                                                            *
 * This software is distributed in the hope that it will be useful,           *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of             *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU           *
 * Lesser General Public License for more details.                            *
 *                                                                            *
 * You should have received a copy of the GNU Lesser General Public           *
 * License along with this software; if not, write to the Free                *
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA         *
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.                   *
 ******************************************************************************/
package org.gatein.sso.josso.plugin;

import org.josso.gateway.identity.exceptions.NoSuchUserException;
import org.josso.gateway.identity.exceptions.SSOIdentityException;
import org.josso.gateway.identity.service.BaseRole;
import org.josso.gateway.identity.service.BaseUser;
import org.josso.gateway.identity.service.BaseUserImpl;
import org.josso.gateway.identity.service.store.UserKey;
import org.josso.gateway.identity.service.store.IdentityStore;

import org.josso.auth.Credential;
import org.josso.auth.CredentialKey;
import org.josso.auth.CredentialProvider;
import org.josso.auth.scheme.AuthenticationScheme;
import org.josso.auth.BindableCredentialStore;
import org.josso.auth.exceptions.SSOAuthenticationException;


/**
 * Identity plugin implementation for JOSSO 1
 *
 * @org.apache.xbean.XBean element="gatein-store"
 * 
 * @author <a href="mailto:sshah@redhat.com">Sohil Shah</a>
 * 
 */
public class GateinIdentityPlugin extends AbstractIdentityPlugin implements BindableCredentialStore,IdentityStore
{

	private AuthenticationScheme authenticationScheme = null;

	public void setAuthenticationScheme(AuthenticationScheme authenticationScheme)
	{
		this.authenticationScheme = authenticationScheme;
	}

	// ----------------IdentityStore implementation---------------------------------------
	public boolean userExists(UserKey userKey) throws SSOIdentityException
	{		
		return true;
	}

	public BaseRole[] findRolesByUserKey(UserKey userKey)
			throws SSOIdentityException
	{
      // Return empty role set for now. We may think about extending auth-callback for obtain GateIn roles via REST.
      return new BaseRole[] {};
	}

	public BaseUser loadUser(UserKey userKey) throws NoSuchUserException,
			SSOIdentityException
	{		
		BaseUser user = new BaseUserImpl(); 
		user.setName(userKey.toString());
		return user;
	}

	// ---------------CredentialStore implementation----------------------------------------------------------
	public Credential[] loadCredentials(CredentialKey credentialKey,
			CredentialProvider credentialProvider) throws SSOIdentityException
	{		
		return null;
	}
	
	public Credential[] loadCredentials(CredentialKey credentialKey) throws SSOIdentityException
	{
		return null;
	}

   public String loadUID(CredentialKey key, CredentialProvider cp) throws SSOIdentityException
   {
      return null;
   }

	public boolean bind(String username, String password) throws SSOAuthenticationException
	{
		try
		{
			return bindImpl(username, password);
		}
		catch(Exception e)
		{
			throw new SSOAuthenticationException(e);
		}
	}
}
