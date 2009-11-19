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

import org.apache.log4j.Logger;

import com.sun.identity.authentication.spi.AMLoginModule;
import com.sun.identity.authentication.spi.AuthLoginException;
import com.sun.identity.authentication.util.ISAuthConstants;

/**
 * @author <a href="mailto:sshah@redhat.com">Sohil Shah</a>
 */
public class AuthenticationPlugin extends AMLoginModule
{
	private static Logger log = Logger.getLogger(AuthenticationPlugin.class);
	
	public AuthenticationPlugin()
	{
		
	}
	
	public void init(Subject subject, Map sharedState, Map options) 
	{
		
	}
	
	public int process(Callback[] callbacks, int state) throws AuthLoginException 
  {
		System.out.println("---------------------------------------------------------------------");
		System.out.println("Performing GateIn Login..............................................");
		System.out.println("---------------------------------------------------------------------");
		
		for(int i=0; i<callbacks.length; i++)
		{
			Callback callback = callbacks[i];
			
			if(callback instanceof NameCallback)
			{
				System.out.println("Username: "+((NameCallback)callback).getName());
			}
			else if(callback instanceof PasswordCallback)
			{
				System.out.println("Password: "+new String(((PasswordCallback)callback).getPassword()));
			}
		}
		
		return ISAuthConstants.LOGIN_SUCCEED;
  }
	
	public Principal getPrincipal()
	{
		return new GateInPrincipal("user");
	}		
}
