/*
 * JBoss, a division of Red Hat
 * Copyright 2011, Red Hat Middleware, LLC, and individual
 * contributors as indicated by the @authors tag. See the
 * copyright.txt in the distribution for a full listing of
 * individual contributors.
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

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;

import org.exoplatform.container.web.AbstractFilter;

/**
 * Filter is needed because when fallback to FORM authentication, we don't need to redirect request to /dologin, which is secured URI,
 * but we need to go directly to /initiatelogin without going again through Tomcat authenticator.
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class SPNEGOFilter extends AbstractFilter
{

   public static final String ATTR_INITIAL_URI = "SPNEGOFilter.initialURI";

   public void doFilter(ServletRequest request, ServletResponse response,
   		FilterChain chain) throws IOException, ServletException
   {
		HttpServletRequest httpRequest = (HttpServletRequest)request;
      HttpServletResponse httpResponse = (HttpServletResponse)response;
   	try
      {

         // first save initialURI as parameter into HTTP session. We may need it later in authenticator
         String initialURI = httpRequest.getParameter("initialURI");
         if (initialURI != null)
         {
            httpRequest.getSession().setAttribute(ATTR_INITIAL_URI, initialURI);
         }

         // we need to redirect directly to initiatelogin without going through secured URL.
         HttpServletResponse wrapperResponse = new IgnoreRedirectHttpResponse(httpResponse);
			chain.doFilter(request, wrapperResponse);
         httpResponse.sendRedirect(httpRequest.getContextPath() + "/initiatelogin");
      }
      catch(Throwable t)
      {
         throw new RuntimeException(t);
      }
   }

   public void destroy()
   {
   }

   // Ignoring calls to response.sendRedirect, which are performed from PortalLoginController
   private class IgnoreRedirectHttpResponse extends HttpServletResponseWrapper
   {

      public IgnoreRedirectHttpResponse(HttpServletResponse response)
      {
         super(response);
      }

      @Override
      public void sendRedirect(String location)
      {
      }

   }
}
