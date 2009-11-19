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

import org.apache.log4j.Logger;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.GetMethod;

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
	private static Logger log = Logger.getLogger(AuthenticationPlugin.class);
	
	private String gateInHost;
	private String gateInPort;
	private String gateInContext;
	
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
	//-----------------------------------------------------------------------------------------------------------------------------------------------------------------
	public boolean authenticateUsernamePasswordInternal(final UsernamePasswordCredentials credentials) 
	{
		try
		{
	    final String username = credentials.getUsername();
	    final String password = credentials.getPassword();
	    
	    StringBuilder urlBuffer = new StringBuilder();
	    urlBuffer.append("http://"+this.gateInHost+":"+this.gateInPort+"/"+this.gateInContext+"/rest/sso/authcallback/auth/"+username+"/"+password);
	    
	    log.debug("-------------------------------------------------------------------");
	    log.debug("REST Request="+urlBuffer.toString());
	    log.debug("-------------------------------------------------------------------");
	
	    return this.executeRemoteCall(urlBuffer.toString());
		}
		catch(Exception e)
		{
			log.error("Remote Authentication Failed--------------------------");
			log.error(this, e);
			return false;
		}
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
			
			switch(status)
			{
				case 200:
					if(response.equals(Boolean.TRUE.toString()))
					{
						return true;
					}
				break;
			}
			
			return false;
		}
		finally
		{
			if(method != null)
			{
				method.releaseConnection();
			}
		}
	}
}
