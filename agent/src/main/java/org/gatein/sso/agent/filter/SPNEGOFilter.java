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
package org.gatein.sso.agent.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.exoplatform.container.web.AbstractFilter;
import org.exoplatform.services.security.Authenticator;
import org.exoplatform.services.security.IdentityRegistry;
import org.exoplatform.services.security.Identity;

/**
 * Note: This Filter should not be needed anymore. Once various SPNEGO scenarios have been tested and stabilized, I would recommend removing this from the codebase in 
 * a future release of the module
 * 
 * @author <a href="mailto:sshah@redhat.com">Sohil Shah</a>
 */
public class SPNEGOFilter extends AbstractFilter
{
	
	public void doFilter(ServletRequest request, ServletResponse response,
			FilterChain chain) throws IOException, ServletException
	{
		HttpServletRequest httpRequest = (HttpServletRequest)request;		
		try
		{
			String remoteUser = httpRequest.getRemoteUser();
									
			if(remoteUser != null)
			{								
				//Check and make sure the IdentityRegistry is consistent
				IdentityRegistry identityRegistry = (IdentityRegistry) getContainer()
						.getComponentInstanceOfType(IdentityRegistry.class);
				if(identityRegistry.getIdentity(remoteUser) == null)
				{
					Authenticator authenticator = (Authenticator) getContainer()
					.getComponentInstanceOfType(Authenticator.class);
					
					Identity identity = authenticator.createIdentity(remoteUser);
					
					identityRegistry.register(identity);
				}
			}
			
			chain.doFilter(request, response);						
		}
		catch(Throwable t)
		{						
			throw new RuntimeException(t);
		}
	}

	public void destroy()
	{
	}
}
