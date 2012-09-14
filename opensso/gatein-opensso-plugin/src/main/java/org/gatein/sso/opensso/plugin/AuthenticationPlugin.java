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

import com.sun.identity.authentication.spi.AMLoginModule;
import com.sun.identity.authentication.spi.AuthLoginException;
import com.sun.identity.authentication.util.ISAuthConstants;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.gatein.sso.plugin.RestCallbackCaller;

/**
 * @author <a href="mailto:sshah@redhat.com">Sohil Shah</a>
 */
public class AuthenticationPlugin extends AMLoginModule
{
   private static final Log log = LogFactory.getLog(AuthenticationPlugin.class);

   private RestCallbackCaller restCallbackCaller;
	private String username;

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

         String gateInHost = properties.getProperty("host");
         String gateInPort = properties.getProperty("port");
         String gateInContext = properties.getProperty("context");
         String gateInProtocol = properties.getProperty("protocol");
         String gateInHttpMethod = properties.getProperty("httpMethod");

         log.debug("GateIn Host: " + gateInHost + ", GateIn Port: " + gateInPort + ", GateIn context: " + gateInContext + ", Protocol=" + gateInProtocol + ", http method=" + gateInHttpMethod);
         this.restCallbackCaller = new RestCallbackCaller(gateInProtocol, gateInHost, gateInPort, gateInContext, gateInHttpMethod);
		}
		catch(IOException ioe)
		{
         log.error("Error during initialization of login module", ioe);
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
         String password = null;
			for (int i = 0; i < callbacks.length; i++)
			{
				Callback callback = callbacks[i];
	
				if (callback instanceof NameCallback)
				{
					this.username = ((NameCallback) callback).getName();					
				}
				else if (callback instanceof PasswordCallback)
				{
					password = new String(((PasswordCallback) callback).getPassword());
				}
			}
				
			boolean success = restCallbackCaller.executeRemoteCall(this.username, password);
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
}
