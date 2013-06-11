/*
 * JBoss, a division of Red Hat
 * Copyright 2012, Red Hat Middleware, LLC, and individual
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

package org.gatein.sso.integration;

import org.exoplatform.container.web.AbstractFilter;
import org.gatein.common.logging.Logger;
import org.gatein.common.logging.LoggerFactory;
import org.gatein.sso.agent.filter.api.SSOInterceptor;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Iterator;
import java.util.Map;

/**
 * Filter will delegate to SSO interceptors
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class SSODelegateFilter extends AbstractFilter
{
   private volatile Map<SSOInterceptor, String> ssoInterceptors;

   private static final Logger log = LoggerFactory.getLogger(SSODelegateFilter.class);

   public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException
   {
      if (SSOUtils.isSSOEnabled())
      {
         SSOFilterChain ssoChain = new SSOFilterChain(chain, getInterceptors(), this);
         ssoChain.doFilter(request, response);
      }
      else
      {
         chain.doFilter(request, response);
      }
   }

   private Map<SSOInterceptor, String> getInterceptors()
   {
      if (ssoInterceptors == null)
      {
         synchronized (this)
         {
            if (ssoInterceptors == null)
            {
               SSOFilterIntegrator ssoFilterIntegrator = (SSOFilterIntegrator)getContainer().getComponentInstanceOfType(SSOFilterIntegrator.class);
               ssoInterceptors = ssoFilterIntegrator.getSSOInterceptors();
               log.info("Initialized SSO integrator with interceptors: " + ssoInterceptors);
            }
         }
      }

      return ssoInterceptors;
   }

   public void destroy()
   {
   }

   public static class SSOFilterChain implements FilterChain
   {

      private final FilterChain containerChain;
      private final Iterator<Map.Entry<SSOInterceptor, String>> iterator;
      private final SSODelegateFilter ssoDelegateFilter;

      public SSOFilterChain(FilterChain containerChain, Map<SSOInterceptor, String> interceptors, SSODelegateFilter ssoDelegateFilter)
      {
         this.containerChain = containerChain;
         this.iterator = interceptors.entrySet().iterator();
         this.ssoDelegateFilter = ssoDelegateFilter;
      }

      public void doFilter(ServletRequest request, ServletResponse response) throws IOException, ServletException
      {
         while (iterator.hasNext())
         {
            Map.Entry<SSOInterceptor, String> current = iterator.next();
            HttpServletRequest hRequest = (HttpServletRequest) request;
            if (log.isTraceEnabled())
            {
               log.trace("Trying mapping " + current.getValue() + " of SSO interceptor " + current.getKey()
                     + ". Request URI is " + hRequest.getRequestURI());
            }

            if (ssoDelegateFilter.isMappedTo(current.getValue(), hRequest.getServletPath()))
            {
               SSOInterceptor interceptor = current.getKey();
               if (log.isTraceEnabled())
               {
                  log.trace("Going to invoke SSO interceptor " + interceptor);
               }
               interceptor.doFilter(request, response, this);
               return;
            }
         }

         if (log.isTraceEnabled())
         {
            log.trace("No more SSO interceptors. Going to invoke container filter chain " + containerChain);
         }
         containerChain.doFilter(request, response);
         return;
      }
   }

   // Primitive impl, but seems to be sufficient for our purposes. Could be overriden if needed
   protected boolean isMappedTo(String filterMapping, String contextPath)
   {
      if ("/*".equals(filterMapping))
      {
         return true;
      }
      else if (contextPath.startsWith(filterMapping))
      {
         return true;
      }

      return false;
   }
}
