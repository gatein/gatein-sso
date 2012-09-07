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

import java.util.Properties;
import java.util.Map;
import java.io.InputStream;
import java.io.IOException;

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
	
	private String username;
	private String password;

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
		InputStream is = null;
		try
		{
			//Load the GateIn properties
			Properties properties = new Properties();
			is = Thread.currentThread().getContextClassLoader().getResourceAsStream("gatein.properties");
			properties.load(is);
			
			this.gateInHost = properties.getProperty("host");
			this.gateInPort = properties.getProperty("port");
			this.gateInContext = properties.getProperty("context");
		}
		catch(IOException ioe)
		{
			
		}
		finally
		{
			if(is != null)
			{
				try{is.close();}catch(Exception e){}
			}
		}
	}

	public int process(Callback[] callbacks, int state) throws AuthLoginException
	{
		try
		{
			for (int i = 0; i < callbacks.length; i++)
			{
				Callback callback = callbacks[i];
	
				if (callback instanceof NameCallback)
				{
					this.username = ((NameCallback) callback).getName();					
				}
				else if (callback instanceof PasswordCallback)
				{
					this.password = new String(((PasswordCallback) callback).getPassword());
				}
			}
	
			StringBuilder urlBuffer = new StringBuilder();
			urlBuffer.append("http://" + this.gateInHost + ":" + this.gateInPort + "/"
					+ this.gateInContext + "/rest/sso/authcallback/auth/" + username + "/"
					+ password);
				
			boolean success = this.executeRemoteCall(urlBuffer.toString());
			if(!success)
			{
				throw new AuthLoginException("GateIn Login Callback Failed!!");
			}
	
			return ISAuthConstants.LOGIN_SUCCEED;
		}
		catch(Throwable e)
		{			
			throw new AuthLoginException(e);
		}
	}

	public Principal getPrincipal()
	{
		return new GateInPrincipal(this.username);
	}
	//--------------------------------------------------------------------------------------------------------------------------------------------------------------------
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

         System.err.println("Callback login failed. " +
               "Response status: " + status);
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
