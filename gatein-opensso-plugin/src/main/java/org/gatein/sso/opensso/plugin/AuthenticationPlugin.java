/*
 * JBoss, a division of Red Hat
 * Copyright 2006, Red Hat Middleware, LLC, and individual contributors as indicated
 * by the @authors tag. See the copyright.txt in the distribution for a
 * full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.gatein.sso.opensso.plugin;

import java.util.Map;
import java.security.Principal;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.GetMethod;

import com.sun.identity.authentication.spi.AMLoginModule;
import com.sun.identity.authentication.spi.AuthLoginException;
import com.sun.identity.authentication.util.ISAuthConstants;

/**
 * @author <a href="mailto:sshah@redhat.com">Sohil Shah</a>
 */
public class AuthenticationPlugin extends AMLoginModule
{
	private String gateInHost;
	private String gateInPort;
	private String gateInContext;

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

	public AuthenticationPlugin()
	{

	}

	public void init(Subject subject, Map sharedState, Map options)
	{
		//TODO: make this configurable
		this.gateInHost = "localhost";
		this.gateInPort = "8080";
		this.gateInContext = "portal";
	}

	public int process(Callback[] callbacks, int state) throws AuthLoginException
	{
		try
		{
			System.out.println("---------------------------------------------------------------------");
			System.out.println("Performing GateIn Login..............................................");
			System.out.println("---------------------------------------------------------------------");
	
			String username = null;
			String password = null;
			for (int i = 0; i < callbacks.length; i++)
			{
				Callback callback = callbacks[i];
	
				if (callback instanceof NameCallback)
				{
					username = ((NameCallback) callback).getName();
					System.out.println("Username: " + username);
				}
				else if (callback instanceof PasswordCallback)
				{
					password = new String(((PasswordCallback) callback).getPassword());
					System.out.println("Password: " + password);
				}
			}
	
			StringBuilder urlBuffer = new StringBuilder();
			urlBuffer.append("http://" + this.gateInHost + ":" + this.gateInPort + "/"
					+ this.gateInContext + "/rest/sso/authcallback/auth/" + username + "/"
					+ password);
	
			System.out.println("-------------------------------------------------------------------");
			System.out.println("REST Request=" + urlBuffer.toString());
			System.out.println("-------------------------------------------------------------------");
			
			System.out.println("About to execute REST call........");
			boolean success = this.executeRemoteCall(urlBuffer.toString());
			
			System.out.println("REST Call was a success....("+success+")");
	
			return ISAuthConstants.LOGIN_SUCCEED;
		}
		catch(Throwable e)
		{
			System.out.println("------------------------------------------------------");
			System.out.println("Exception :"+e.toString());
			System.out.println("Message :"+e.getMessage());
			System.out.println("------------------------------------------------------");
			e.printStackTrace();
			throw new AuthLoginException(e);
		}
	}

	public Principal getPrincipal()
	{
		return new GateInPrincipal("demo");
	}

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
