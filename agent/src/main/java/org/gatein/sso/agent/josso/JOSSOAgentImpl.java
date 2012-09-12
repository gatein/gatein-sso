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
package org.gatein.sso.agent.josso;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.exoplatform.container.xml.InitParams;
import org.gatein.common.logging.Logger;
import org.gatein.common.logging.LoggerFactory;
import org.gatein.sso.agent.GenericAgent;

import org.josso.agent.Lookup;
import org.josso.agent.SSOAgentRequest;
import org.josso.agent.SSOPartnerAppConfig;
import org.josso.agent.SingleSignOnEntry;
import org.josso.agent.http.HttpSSOAgent;

/**
 * @author <a href="mailto:sshah@redhat.com">Sohil Shah</a>
 */
public class JOSSOAgentImpl extends GenericAgent implements JOSSOAgent
{
	private static Logger log = LoggerFactory.getLogger(JOSSOAgentImpl.class);
	
	private HttpSSOAgent httpAgent;         
	
	public JOSSOAgentImpl(InitParams params)
	{
		try
		{
	      this.httpAgent = JOSSOUtils.lookupSSOAgent();
	      this.httpAgent.start();

         log.info("JOSSO agent started successfuly!");
		}
		catch(Exception e)
		{
			log.error(this, e);
			throw new RuntimeException(e);
		}
	}


   public void validateTicket(HttpServletRequest httpRequest,HttpServletResponse httpResponse) throws Exception
	{
		String ticket = httpRequest.getParameter("josso_assertion_id");
		log.debug("Trying to validate the following Ticket: " + ticket);
		
      String requester = JOSSOUtils.getPartnerAppId(httpAgent, httpRequest);

		//Use the JOSSO Client Library to validate the token and extract the subject that was authenticated
		SSOAgentRequest agentRequest = this.doMakeSSOAgentRequest(requester, SSOAgentRequest.ACTION_RELAY,
		null, ticket, httpRequest, httpResponse);
		
		SingleSignOnEntry entry = this.httpAgent.processRequest(agentRequest);
		
		if(entry != null)
		{
			String sessionId = agentRequest.getSessionId();
			String assertionId = agentRequest.getAssertionId();
			String principal = entry.principal.getName();

			log.debug("SessionId: " + sessionId);
			log.debug("AssertionId: " + assertionId);
			log.debug("Principal: " + principal);
			
         this.saveSSOCredentials(principal, httpRequest);
		}
	}


	protected SSOAgentRequest doMakeSSOAgentRequest(String requester, int action, String sessionId, String assertionId,
                                                    HttpServletRequest hreq, HttpServletResponse hres) 
	{
      return GateInJOSSOAgentFactory.getInstance().getSSOAgentRequest(requester, action, sessionId,assertionId, hreq, hres);
   }
}
