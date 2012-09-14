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
package org.gatein.sso.cas.plugin;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.gatein.sso.plugin.RestCallbackCaller;
import org.jasig.cas.authentication.handler.support.AbstractUsernamePasswordAuthenticationHandler;
import org.jasig.cas.authentication.principal.UsernamePasswordCredentials;

/**
 * This is a Gatein Authentication Plugin for the CAS server. It is deployed along with the CAS server and provides authentication
 * against a Gatein instance
 * 
 * @author <a href="mailto:sshah@redhat.com">Sohil Shah</a>
 */
public class AuthenticationPlugin extends AbstractUsernamePasswordAuthenticationHandler
{
   private static final Log log = LogFactory.getLog(AuthenticationPlugin.class);

   private String gateInProtocol;
	private String gateInHost;
	private String gateInPort;
	private String gateInContext;
   private String httpMethod;
   private RestCallbackCaller restCallbackCaller;
	
	public AuthenticationPlugin()
	{
		
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

   public String getGateInProtocol()
   {
      return gateInProtocol;
   }

   public void setGateInProtocol(String gateInProtocol)
   {
      this.gateInProtocol = gateInProtocol;
   }

   public String getHttpMethod()
   {
      return httpMethod;
   }

   public void setHttpMethod(String httpMethod)
   {
      this.httpMethod = httpMethod;
   }


	//-----------------------------------------------------------------------------------------------------------------------------------------------------------------
	public boolean authenticateUsernamePasswordInternal(final UsernamePasswordCredentials credentials) 
	{
      getRestCallbackCaller();
      try
      {
         final String username = credentials.getUsername();
         final String password = credentials.getPassword();

         return getRestCallbackCaller().executeRemoteCall(username, password);
      }
      catch(Exception e)
      {
         log.error("Remote Authentication Failed");
         log.error(this, e);
         return false;
      }
  }

   // Needs to be lazily initialized after all properties are injected by Spring
   private RestCallbackCaller getRestCallbackCaller()
   {
      if (restCallbackCaller == null)
      {
         synchronized (this)
         {
            if (restCallbackCaller == null)
            {
               restCallbackCaller = new RestCallbackCaller(gateInProtocol, gateInHost, gateInPort,
                     gateInContext, httpMethod);
            }
         }
      }

      return restCallbackCaller;
   }
}
