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

import org.gatein.sso.agent.josso.JOSSOUtils;
import org.gatein.wci.ServletContainerFactory;
import org.josso.agent.AbstractSSOAgent;

import java.io.IOException;
import java.net.URLEncoder;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

//Works for GateIn Portal Logout URL = {AnyURL}?portal:componentId=UIPortal&portal:action=Logout

/**
 * Usage:
 * 
 * Add the following to portal.war/WEB-INF/web.xml
 * 
 * <filter>                                                                                                                                     
 *   <filter-name>JOSSOLogoutFilter</filter-name>                                                                                              
 *     <filter-class>org.gatein.sso.agent.filter.JOSSOLogoutFilter</filter-class>                                                      
 *     <init-param>                                 
 *       <!-- This should point to your JOSSO authentication server -->                                                                                              
 *       <param-name>LOGOUT_URL</param-name>                                                                                                
 *       <param-value>http://localhost:8888/josso/signon/logout.do</param-value>                                                                                                         
 *     </init-param>                                                                                                                              
 * </filter>   
 * 
 * <filter-mapping>
 *    <filter-name>JOSSOLogoutFilter</filter-name>
 *    <url-pattern>/*</url-pattern>
 *  </filter-mapping>
 *
 * 
 * 
 */


/**
 * @author <a href="mailto:sshah@redhat.com">Sohil Shah</a>
 */
public class JOSSOLogoutFilter extends AbstractLogoutFilter
{
   private AbstractSSOAgent jossoAgent;

   @Override
   protected void initImpl()
   {
      super.initImpl();

      try
      {
         // Lookup for JOSSO agent
         jossoAgent = JOSSOUtils.lookupSSOAgent();

         // If logoutURL not provided from filter configuration, fallback to obtain it from JOSSO agent
         if (logoutUrl == null || logoutUrl.length() == 0)
         {
            logoutUrl = jossoAgent.getGatewayLogoutUrl();
            log.info("Obtained logoutUrl from configuration of josso agent. logoutUrl: " + this.logoutUrl);
         }
      }
      catch (Exception e)
      {
         log.warn("Can't obtain JOSSO agent", e);
      }
   }

   public void doFilter(ServletRequest request, ServletResponse response,
                        FilterChain chain) throws IOException, ServletException
   {
      HttpServletRequest httpRequest = (HttpServletRequest) request;
      HttpServletResponse httpResponse = (HttpServletResponse) response;

      boolean isLogoutInProgress = this.isLogoutInProgress(httpRequest);

      if (isLogoutInProgress)
      {
         boolean redirectionSent = handleLogout(httpRequest, httpResponse);
         if (redirectionSent)
         {
            return;
         }
      }

      // After JOSSO2 performs logout on it's side, it doesn't redirect to portal logout URL but to "http://localhost:8080/portal/".
      // So we need to check if session attribute is still here, which means that we just returned from JOSSO logout.
      // Explicit portal logout is needed in this case
      if (httpRequest.getSession().getAttribute(SSO_LOGOUT_FLAG) != null)
      {
         if (log.isTraceEnabled())
         {
            log.trace("Perform programmatic WCI logout");
         }

         // Programmatic login in WCI
         ServletContainerFactory.getServletContainer().logout(httpRequest, httpResponse);

         String redirectUrl = httpRequest.getContextPath();
         redirectUrl = httpResponse.encodeRedirectURL(redirectUrl);
         httpResponse.sendRedirect(redirectUrl);

         return;
      }

      chain.doFilter(request, response);
   }

   @Override
	protected String getRedirectUrl(HttpServletRequest httpRequest)
	{
		try
		{
			String parameters = URLEncoder.encode(
							"portal:componentId=UIPortal&portal:action=Logout", "UTF-8");
         String partnerAppId = JOSSOUtils.getPartnerAppId(jossoAgent, httpRequest);

         StringBuilder builder = new StringBuilder(this.logoutUrl).append("?josso_back_to=")
               .append(httpRequest.getRequestURL()).append("?").append(parameters)
               .append("&josso_partnerapp_id=").append(partnerAppId);
			
			return builder.toString();
		}
		catch(Exception e)
		{
			throw new RuntimeException(e);
		}
	}
}
