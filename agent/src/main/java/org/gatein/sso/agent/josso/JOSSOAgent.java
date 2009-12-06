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

import org.apache.log4j.Logger;

import org.exoplatform.web.security.Credentials;
import org.gatein.sso.agent.GenericSSOAgent;
import org.josso.agent.SSOAgent;
import org.josso.agent.Lookup;
import org.josso.agent.SSOAgentRequest;
import org.josso.agent.SingleSignOnEntry;

import org.josso.servlet.agent.GenericServletSSOAgentRequest;
import org.josso.servlet.agent.GenericServletLocalSession;

/**
 * TODO: This is broken. This will need a JBoss 5.1.0.GA based JOSSO client stack
 * 
 * @author <a href="mailto:sshah@redhat.com">Sohil Shah</a>
 */
public class JOSSOAgent
{
	private static Logger log = Logger.getLogger(Logger.class);
	private static JOSSOAgent singleton;
	
	private String serverUrl = null;
	
	private JOSSOAgent(String serverUrl)
	{
		this.serverUrl = serverUrl;
	}
	
	public static JOSSOAgent getInstance(String serverUrl)
	{
		if(JOSSOAgent.singleton == null)
		{
			synchronized(JOSSOAgent.class)
			{
				if(JOSSOAgent.singleton == null)
				{
					JOSSOAgent.singleton = new JOSSOAgent(serverUrl);
				}
			}
		}
		return JOSSOAgent.singleton;
	}
	
	public void validateTicket(HttpServletRequest httpRequest) throws Exception
	{
		String ticket = httpRequest.getParameter("josso_assertion_id");
		log.info("Trying to validate the following Ticket: "+ticket);
		
		//TODO: Use the JOSSO Client Library to validate the token and extract the subject that was authenticated
		
		//Just do a hack login for now...to cutoff the infinite redirects
		Credentials credentials = new Credentials("demo", "");
		httpRequest.getSession().setAttribute(GenericSSOAgent.CREDENTIALS, credentials);
	}
}
