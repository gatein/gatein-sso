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

import java.io.InputStream;
import java.util.Properties;

import org.apache.log4j.Logger;

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

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.GetMethod;

/**
 * @org.apache.xbean.XBean element="gatein-store"
 * 
 * @author <a href="mailto:sshah@redhat.com">Sohil Shah</a>
 * 
 */
public class GateinIdentityPlugin implements BindableCredentialStore,IdentityStore
{
	private static Logger log = Logger.getLogger(GateinIdentityPlugin.class);

	private AuthenticationScheme authenticationScheme = null;

	private String gateInHost;
	private String gateInPort;
	private String gateInContext;

	/**
    * 
    *
    */
	public GateinIdentityPlugin()
	{
		InputStream is = null;
		try
		{
			///Load the GateIn properties
			Properties properties = new Properties();
			is = Thread.currentThread().getContextClassLoader().getResourceAsStream("gatein.properties");
			properties.load(is);
			
			this.gateInHost = properties.getProperty("host");
			this.gateInPort = properties.getProperty("port");
			this.gateInContext = properties.getProperty("context");

			log
					.info("-------------------------------------------------------------------");
			log.info("GateIn Host: " + this.gateInHost);
			log
					.info("GateIn Identity Plugin successfully started........................");
			log
					.info("-------------------------------------------------------------------");
		}
		catch (Exception e)
		{
			this.authenticationScheme = null;

			log.error(this, e);
			throw new RuntimeException(
					"GateIn Identity Plugin registration failed....");
		}
		finally
		{
			if(is != null)
			{
				try{is.close();}catch(Exception e){}
			}
		}
	}

	public void setAuthenticationScheme(AuthenticationScheme authenticationScheme)
	{
		this.authenticationScheme = authenticationScheme;
	}

	public String getGateInHost()
	{
		return gateInHost;
	}

	public void setGateInHost(String gateInHost)
	{
		this.gateInHost = gateInHost;
	}

	public String getGateInPort()
	{
		return gateInPort;
	}

	public void setGateInPort(String gateInPort)
	{
		this.gateInPort = gateInPort;
	}

	public String getGateInContext()
	{
		return gateInContext;
	}

	public void setGateInContext(String gateInContext)
	{
		this.gateInContext = gateInContext;
	}

	// ----------------IdentityStore
	// implementation------------------------------------------------------------------------------------------------------------------------
	public boolean userExists(UserKey userKey) throws SSOIdentityException
	{		
		return true;
	}

	public BaseRole[] findRolesByUserKey(UserKey userKey)
			throws SSOIdentityException
	{	
			return null;
	}

	public BaseUser loadUser(UserKey userKey) throws NoSuchUserException,
			SSOIdentityException
	{		
		BaseUser user = new BaseUserImpl(); 
		user.setName(userKey.toString());
		return user;
	}
	// ---------------CredentialStore
	// implementation----------------------------------------------------------------------------------------------------------------------
	public Credential[] loadCredentials(CredentialKey credentialKey,
			CredentialProvider credentialProvider) throws SSOIdentityException
	{		
		return null;
	}
	
	public Credential[] loadCredentials(CredentialKey credentialKey) throws SSOIdentityException
	{
		return null;
	}

	public boolean bind(String username, String password)
			throws SSOAuthenticationException
	{
		try
		{
			// return this.portalIdentityService.authenticate(username, password);
			log.debug("Performing Authentication........................");
			log.debug("Username: "+username);
			log.debug("Password: "+password);
			
			StringBuilder urlBuffer = new StringBuilder();
				urlBuffer.append("http://" + this.gateInHost + ":" + this.gateInPort + "/"
						+ this.gateInContext + "/rest/sso/authcallback/auth/" + username + "/"
						+ password);
					
			boolean success = this.executeRemoteCall(urlBuffer.toString());
				
			return success;
		}
		catch(Exception e)
		{
			throw new SSOAuthenticationException(e);
		}
	}
	//------------------------------------------------------------------------------------------------------------------------------------------
	private boolean executeRemoteCall(String authUrl) throws Exception
	{
		HttpClient client = new HttpClient();
		GetMethod method = null;
		try
		{
			method = new GetMethod(authUrl);

			int status = client.executeMethod(method);
			String response = method.getResponseBodyAsString();

			switch (status)
			{
				case 200:
				if (response.equals(Boolean.TRUE.toString()))
				{
					return true;
				}
				break;
			}

			return false;
		}
		finally
		{
			if (method != null)
			{
				method.releaseConnection();
			}
		}
	}
}
