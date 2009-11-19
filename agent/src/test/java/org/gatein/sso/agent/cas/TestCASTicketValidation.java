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

import junit.framework.TestCase;

import org.jasig.cas.client.validation.Cas20ProxyTicketValidator;
import org.jasig.cas.client.validation.Assertion;

/**
 * @author <a href="mailto:sshah@redhat.com">Sohil Shah</a>
 */
public class TestCASTicketValidation extends TestCase
{
	private static Logger log = Logger.getLogger(TestCASTicketValidation.class);

	protected static final String CONST_CAS_SERVER_URL = "http://localhost:8080/cas";

	protected void setUp() throws Exception
	{
		
	}

	protected void tearDown() throws Exception
	{
		
	}

	public void testSimpleTicket() throws Exception
	{
		log.info("Starting simple cas validation test case..........................");
		
		Cas20ProxyTicketValidator ticketValidator = new Cas20ProxyTicketValidator(CONST_CAS_SERVER_URL);
    ticketValidator.setRenew(true);
    Assertion assertion = ticketValidator.validate("ST-3-zm9wIaIGgoKZdb7vh0MU-cas", "http://localhost:1500/portal/private/classic"); 
    
    log.info("------------------------------------------------------------------------------------");
    log.info("Principal: "+assertion.getPrincipal().getName());
    log.info("------------------------------------------------------------------------------------");
	}
}
