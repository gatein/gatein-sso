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

import org.apache.log4j.Logger;

import junit.framework.TestCase;

import org.josso.agent.SSOAgent;
import org.josso.agent.Lookup;
import org.josso.agent.SSOAgentRequest;
import org.josso.agent.SingleSignOnEntry;

import org.josso.servlet.agent.GenericServletSSOAgentRequest;
import org.josso.servlet.agent.GenericServletLocalSession;

/**
 * @author <a href="mailto:sshah@redhat.com">Sohil Shah</a>
 */
public class TestAssertionValidation extends TestCase
{
	private static Logger log = Logger.getLogger(TestAssertionValidation.class);

	
	protected void setUp() throws Exception
	{
		
	}

	protected void tearDown() throws Exception
	{
		
	}

	public void testSimpleAssertion() throws Exception
	{
		log.info("Starting simple josso assertion test case..........................");
		
		Lookup lookup = Lookup.getInstance();
		lookup.init("josso-agent-config.xml");
		
		SSOAgent agent = lookup.lookupSSOAgent();

		log.info("Agent: "+agent);
		
		String assertionId = "";
		
		SSOAgentRequest request = new GenericServletSSOAgentRequest("portal", SSOAgentRequest.ACTION_RELAY,
				null,
				new GenericServletLocalSession(null),
				assertionId);
		
		SingleSignOnEntry result = agent.processRequest(request);
		log.info("SSO Info: "+result);		
	}
}
