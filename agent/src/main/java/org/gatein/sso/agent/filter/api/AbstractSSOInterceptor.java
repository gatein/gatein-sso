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

import org.exoplatform.container.web.AbstractFilter;
import org.exoplatform.container.xml.InitParams;
import org.exoplatform.container.xml.ValueParam;
import org.gatein.common.logging.Logger;
import org.gatein.common.logging.LoggerFactory;

import javax.servlet.FilterConfig;
import javax.servlet.ServletException;

/**
 * Base {@link SSOInterceptor} which adds possibility to be initialized either through Servlet API or through eXo kernel
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public abstract class AbstractSSOInterceptor extends AbstractFilter implements SSOInterceptor
{
   private FilterConfig filterConfig;
   private InitParams params;

   private static final Logger log = LoggerFactory.getLogger(AbstractSSOInterceptor.class);


   /**
    * Method is invoked if we are performing initialization through servlet api (web filter)
    */
   @Override
   protected final void afterInit(FilterConfig filterConfig) throws ServletException
   {
      initImpl(filterConfig, null);
   }

   /**
    * Method is invoked if we are performing initialization through exo kernel
    */
   public final void initWithParams(InitParams params)
   {
      initImpl(null, params);
   }

   /**
    * initialization for both cases. Exactly one parameter (filterConfig or params) must be non-null
    *
    * @param filterConfig parameter is non-null if we initialize through servlet api
    * @param params  parameter is non-null if we initialize through kernel
    */
   private void initImpl(FilterConfig filterConfig, InitParams params)
   {
      if (filterConfig != null)
      {
         this.filterConfig = filterConfig;
         log.debug(this + " interceptor initialized through Servlet API");
      }

      if (params != null)
      {
         this.params = params;
         log.debug(this + " interceptor initialized through eXo kernel");
      }

      initImpl();
   }

   /**
    * This method needs to be implemented by conrete filter. Filter should obtain it's init parameters by calling
    * {@link #getInitParameter(String)}. This works in both types of initialization
    * (Case1: Filter initialization through kernel, Case2: initialization through servlet API)
    */
   protected abstract void initImpl();

   /**
    * Read init parameter (works for both kernel initialization or Servlet API initialization)
    *
    * @param paramName parameter name
    * @return parameter value
    */
   protected String getInitParameter(String paramName)
   {
      if (params != null)
      {
         ValueParam param = params.getValueParam(paramName);
         return param==null ? null : param.getValue();
      }

      return filterConfig.getInitParameter(paramName);
   }

   /**
    * {@inheritDoc}
    */
   public void setFilterConfig(FilterConfig config)
   {
      // Updating config of AbstractFilter
      this.config = config;
   }
}
