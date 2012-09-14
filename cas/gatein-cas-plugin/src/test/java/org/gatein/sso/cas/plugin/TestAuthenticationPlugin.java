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

import junit.framework.TestCase;

import org.jasig.cas.authentication.principal.UsernamePasswordCredentials;

/**
 * @author <a href="mailto:sshah@redhat.com">Sohil Shah</a>
 */
public class TestAuthenticationPlugin extends TestCase
{
	private AuthenticationPlugin authPlugin;
	
	public void setUp() throws Exception
	{
		this.authPlugin = new AuthenticationPlugin();
		
		this.authPlugin.setGateInHost("localhost");
		this.authPlugin.setGateInPort("1500");
		this.authPlugin.setGateInContext("portal");
	}
	
	public void tearDown() throws Exception
	{
		this.authPlugin = null;
	}	
	//-------------------------------------------------------------------------------------------------------------------------------------------------------------------
	public void testAuthenticationCallback() throws Exception
	{
		//Unsuccessful login scenario
		UsernamePasswordCredentials credentials = new UsernamePasswordCredentials();
		credentials.setUsername("root");
		credentials.setPassword("blah");
		
		boolean authResult = this.authPlugin.authenticate(credentials);
		assertFalse("Login should *not* have succeeded!!", authResult);
		
		
		//Successful login scenario
		credentials = new UsernamePasswordCredentials();
		credentials.setUsername("root");
		credentials.setPassword("gtn");
		
		authResult = this.authPlugin.authenticate(credentials);
		assertTrue("Login should have succeeded!!", authResult);
	}
}
