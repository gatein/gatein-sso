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

import javax.servlet.http.HttpServletRequest;

import org.exoplatform.container.xml.InitParams;
import org.gatein.common.logging.Logger;
import org.gatein.common.logging.LoggerFactory;
import org.gatein.sso.agent.GenericAgent;
import org.jasig.cas.client.validation.Cas20ProxyTicketValidator;
import org.jasig.cas.client.validation.Assertion;

/**
 * @author <a href="mailto:sshah@redhat.com">Sohil Shah</a>
 */
public class CASAgentImpl extends GenericAgent implements CASAgent
{
	private static Logger log = LoggerFactory.getLogger(CASAgentImpl.class);
	
	private String casServerUrl;
	private boolean renewTicket;
	private String casServiceUrl;
	
	public CASAgentImpl(InitParams params)
	{
		// TODO: Read casServerUrl and casServiceUrl from params
	}

   public void setCasServerUrl(String casServerUrl)
   {
      this.casServerUrl = casServerUrl;
   }

   public void setCasServiceUrl(String casServiceUrl)
   {
      this.casServiceUrl = casServiceUrl;
   }

   public void setRenewTicket(boolean renewTicket)
	{
		this.renewTicket = renewTicket;
	}

	public void validateTicket(HttpServletRequest httpRequest, String ticket) throws Exception
	{		
		Cas20ProxyTicketValidator ticketValidator = new Cas20ProxyTicketValidator(casServerUrl);
	    ticketValidator.setRenew(this.renewTicket);
	    
	    //String serviceUrl = "http://"+ httpRequest.getServerName() +":" + httpRequest.getServerPort() + 
	    //httpRequest.getContextPath() +"/private/classic";
	    Assertion assertion = ticketValidator.validate(ticket, this.casServiceUrl); 
	    
	    log.debug("------------------------------------------------------------------------------------");
	    log.debug("Service: "+this.casServiceUrl);
	    log.debug("Principal: "+assertion.getPrincipal().getName());
	    log.debug("------------------------------------------------------------------------------------");

	    String principal = assertion.getPrincipal().getName();
       this.saveSSOCredentials(principal, httpRequest);
	}		
}
