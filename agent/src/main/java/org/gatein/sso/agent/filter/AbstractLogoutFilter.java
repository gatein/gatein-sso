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

import org.gatein.common.http.QueryStringParser;
import org.gatein.common.logging.Logger;
import org.gatein.common.logging.LoggerFactory;
import org.gatein.sso.agent.filter.api.AbstractSSOInterceptor;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

/**
 * @author <a href="mailto:sshah@redhat.com">Sohil Shah</a>
 */
public abstract class AbstractLogoutFilter extends AbstractSSOInterceptor
{
	protected String logoutUrl;
	private static final String fileEncoding = System.getProperty("file.encoding");

    private static final String SSO_LOGOUT_FLAG = "SSO_LOGOUT_FLAG";
    private static final String SSO_LOGOUT_REQ_URI = "SSO_LOGOUT_REQ_URI";
    private static final String SSO_LOGOUT_REQ_QUERY_STRING = "SSO_LOGOUT_REQ_QUERY_STRING";

   protected final Logger log = LoggerFactory.getLogger(this.getClass());

	protected void initImpl()
	{
		this.logoutUrl = getInitParameter("LOGOUT_URL");

      log.info("Reading filter configuration: logoutUrl=" + this.logoutUrl);
	}

	public void destroy()
	{
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
        // This means that we returned from SSO logout, but we need to redirect request to portal logout URI (something like
        // /portal/classic/home?portal:componentId=UIPortal&portal:action=Logout) because current request is not logout request
        // This can happen with some SSO servers, which doesn't redirect to logout URL (CAS or JOSSO 2.2)
        else if (httpRequest.getSession().getAttribute(SSO_LOGOUT_FLAG) != null)
        {
            // Restore previously saved logout URI
            HttpSession httpSession = httpRequest.getSession();
            String restoredURI = (String)httpSession.getAttribute(SSO_LOGOUT_REQ_URI);
            String restoredQueryString = (String)httpSession.getAttribute(SSO_LOGOUT_REQ_QUERY_STRING);

            // Cleanup all helper session attributes but keep SSO_LOGOUT_FLAG
            httpSession.removeAttribute(SSO_LOGOUT_REQ_URI);
            httpSession.removeAttribute(SSO_LOGOUT_REQ_QUERY_STRING);

            if (restoredURI != null && restoredQueryString != null)
            {
               String portalLogoutURI = restoredURI + "?" + restoredQueryString;
               portalLogoutURI = httpResponse.encodeRedirectURL(portalLogoutURI);
               httpResponse.sendRedirect(portalLogoutURI);

               if (log.isTraceEnabled())
               {
                  log.trace("SSO logout performed. Redirecting to portal logout URI: " + portalLogoutURI);
               }

               return;
            }
        }

		chain.doFilter(request, response);
	}

	protected boolean isLogoutInProgress(HttpServletRequest request) throws UnsupportedEncodingException
	{
		// set character encoding before retrieving request parameters
		if(fileEncoding!=null) 
		{
			request.setCharacterEncoding(fileEncoding);
		}

        String action = null;
        String queryString = request.getQueryString();
        if (queryString != null) {
            // The QueryStringParser currently only likes & and not &amp;
            queryString = queryString.replace("&amp;", "&");
            Map<String, String[]> queryParams = QueryStringParser.getInstance().parseQueryString(queryString);
            String[] portalActions = queryParams.get("portal:action");
            if (portalActions != null && portalActions.length > 0) {
                action = portalActions[0];
            }
        }

		if (action != null && action.equals("Logout"))
		{
			return true;
		}

		return false;
	}

   /**
    * Handle logout on SSO server side
    *
    * @param httpRequest
    * @param httpResponse
    * @return true if redirection to SSO server was send. We need to return immediately from filter invocation then
    * @throws IOException
    */
   protected boolean handleLogout(HttpServletRequest httpRequest, HttpServletResponse httpResponse) throws IOException
   {
      HttpSession httpSession = httpRequest.getSession();

      // We need to perform redirection to SSO server to handle logout on SSO side
      if (httpRequest.getSession().getAttribute(SSO_LOGOUT_FLAG) == null)
      {
         httpSession.setAttribute(SSO_LOGOUT_FLAG, Boolean.TRUE);
         httpSession.setAttribute(SSO_LOGOUT_REQ_URI, httpRequest.getRequestURI());
         httpSession.setAttribute(SSO_LOGOUT_REQ_QUERY_STRING, httpRequest.getQueryString());

         String redirectUrl = this.getRedirectUrl(httpRequest);
         redirectUrl = httpResponse.encodeRedirectURL(redirectUrl);
         httpResponse.sendRedirect(redirectUrl);

         if (log.isTraceEnabled())
         {
            log.trace("Redirecting to SSO logout URL: " + redirectUrl);
         }

         return true;
      }
      else
      {
         // We returned from SSO server. Clear the LOGOUT flag and continue with this httpRequest
         httpSession.removeAttribute(SSO_LOGOUT_FLAG);
         if (log.isTraceEnabled())
         {
            log.trace("SSO logout performed and SSO_LOGOUT_FLAG removed from session. Continue with portal logout");
         }

         return false;
      }
   }
	
	protected abstract String getRedirectUrl(HttpServletRequest httpRequest);
}
