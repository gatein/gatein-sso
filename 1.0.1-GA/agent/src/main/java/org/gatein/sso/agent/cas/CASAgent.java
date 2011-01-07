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
package org.gatein.sso.agent.cas;

import org.apache.log4j.Logger;

import javax.servlet.http.HttpServletRequest;

import org.jasig.cas.client.validation.Cas20ProxyTicketValidator;
import org.jasig.cas.client.validation.Assertion;

import org.exoplatform.web.security.Credentials;

import org.gatein.sso.agent.GenericSSOAgent;

/**
 * @author <a href="mailto:sshah@redhat.com">Sohil Shah</a>
 */
public class CASAgent
{
	private static Logger log = Logger.getLogger(CASAgent.class);
	private static CASAgent singleton;
	
	private String casServerUrl;
	private boolean renewTicket;
	
	private CASAgent(String casServerUrl)
	{
		this.casServerUrl = casServerUrl;
	}
	
	public static CASAgent getInstance(String casServerUrl)
	{
		if(CASAgent.singleton == null)
		{
			synchronized(CASAgent.class)
			{
				if(CASAgent.singleton == null)
				{
					CASAgent.singleton = new CASAgent(casServerUrl);
				}
			}
		}
		return CASAgent.singleton;
	}
	
		
	public boolean isRenewTicket()
	{
		return renewTicket;
	}

	public void setRenewTicket(boolean renewTicket)
	{
		this.renewTicket = renewTicket;
	}

	public void validateTicket(HttpServletRequest httpRequest, String ticket) throws Exception
	{		
		Cas20ProxyTicketValidator ticketValidator = new Cas20ProxyTicketValidator(casServerUrl);
    ticketValidator.setRenew(this.renewTicket);
    
    String serviceUrl = httpRequest.getScheme()+"://"+ httpRequest.getServerName() +":" + httpRequest.getServerPort() + 
    httpRequest.getContextPath() +"/private/classic";
    Assertion assertion = ticketValidator.validate(ticket, serviceUrl); 
    
    log.debug("------------------------------------------------------------------------------------");
    log.debug("Service: "+serviceUrl);
    log.debug("Principal: "+assertion.getPrincipal().getName());
    log.debug("------------------------------------------------------------------------------------");
    
        
    //Use empty password....it shouldn't be needed...this is a SSO login. The password has
    //already been presented with the SSO server. It should not be passed around for 
    //better security
    Credentials credentials = new Credentials(assertion.getPrincipal().getName(), "");
    httpRequest.getSession().setAttribute(GenericSSOAgent.CREDENTIALS, credentials);		    
	}		
}
