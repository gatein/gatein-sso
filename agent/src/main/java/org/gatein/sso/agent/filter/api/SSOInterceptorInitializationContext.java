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

package org.gatein.sso.agent.filter.api;


import org.exoplatform.container.ExoContainer;
import org.exoplatform.container.ExoContainerContext;
import org.exoplatform.container.xml.InitParams;
import org.exoplatform.container.xml.ValueParam;

import javax.servlet.FilterConfig;

/**
 * Context, which encapsulates all initialization configuration about {@link SSOInterceptor} and is able to recognize
 * whether interceptor was initialized through exo kernel or through Servlet API (old way)
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
class SSOInterceptorInitializationContext
{
   private final FilterConfig filterConfig;
   private final InitParams initParams;
   private final ExoContainerContext containerContext;
   private final String containerName;

   // If true, interceptor was initialized through Servlet API. If false, interceptor was initialized through exo kernel.
   private final boolean initializedFromServletAPI;


   SSOInterceptorInitializationContext(FilterConfig filterConfig, InitParams initParams, ExoContainerContext containerContext)
   {
      this.filterConfig = filterConfig;
      this.initParams = initParams;
      this.containerContext = containerContext;
      this.containerName = containerContext == null ? null : containerContext.getName();
      this.initializedFromServletAPI = filterConfig != null;
   }

   String getInitParameter(String paramName)
   {
      if (initParams != null)
      {
         ValueParam param = initParams.getValueParam(paramName);
         return param==null ? null : substitutePortalContainerName(param.getValue());
      }

      return filterConfig.getInitParameter(paramName);
   }



   /**
    * Substitus portal container string @@portal.container.name@@ with portal container name
    * Example: For input like aaa_@@portal.container.name@@_bbb returns something like "aaa_portal_bbb"
    *
    * @param input
    * @return substituted string
    */
   private String substitutePortalContainerName(String input)
   {
      return input.replaceAll(AbstractSSOInterceptor.PORTAL_CONTAINER_SUBSTITUTION_PATTERN, this.containerName);
   }

   boolean isInitializedFromServletAPI()
   {
      return initializedFromServletAPI;
   }

   ExoContainer getExoContainer()
   {
      return containerContext.getContainer();
   }

   public String toString()
   {
      return "SSOInterceptorInitializationContext filterConfig=" + filterConfig
            + ", initParams: " + initParams
            + ", initializedFromServletAPI: " + initializedFromServletAPI
            + ", containerName: " + containerName;
   }
}
