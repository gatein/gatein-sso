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

import java.net.URLEncoder;
import javax.servlet.http.HttpServletRequest;

//Works for GateIn Portal Logout URL = {AnyURL}?portal:componentId=UIPortal&portal:action=Logout

/**
 * Usage:
 * 
 * Add the following to portal.war/WEB-INF/web.xml
 * 
 * <filter>
 *	<filter-name>CASLogoutFilter</filter-name>                                                                                              
 *	<filter-class>org.gatein.sso.agent.filter.CASLogoutFilter</filter-class>                                                      
 * 	<init-param>                                 
 *		<!-- This should point to your CAS authentication server -->                                                                                              
 *	  <param-name>LOGOUT_URL</param-name>                                                                                                
 *		<param-value>http://localhost:8888/cas/logout</param-value>                                                                                                         
 *	</init-param>                                                                                                                              
 *  </filter>   
 * 
 * <filter-mapping>
 *	  <filter-name>CASLogoutFilter</filter-name>
 *	  <url-pattern>/*</url-pattern>
 * </filter-mapping>
 *
 * 
 * 
 */


/**
 * @author <a href="mailto:sshah@redhat.com">Sohil Shah</a>
 */
public class CASLogoutFilter extends AbstractLogoutFilter
{		
	protected String getRedirectUrl(HttpServletRequest httpRequest)
	{
		try
		{
			String parameters = URLEncoder.encode(
							"portal:componentId=UIPortal&portal:action=Logout", "UTF-8");
			
			String redirectUrl = this.logoutUrl+"?url="+httpRequest.getRequestURL()+"?"+parameters;
			
			return redirectUrl;
		}
		catch(Exception e)
		{
			throw new RuntimeException(e);
		}
	}
}
