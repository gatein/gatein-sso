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

import org.exoplatform.container.component.ComponentPlugin;
import org.gatein.common.logging.Logger;
import org.gatein.common.logging.LoggerFactory;
import org.gatein.sso.agent.filter.api.SSOInterceptor;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Kernel component, which holds references to all configured {@link org.gatein.sso.agent.filter.api.SSOInterceptor}
 * instances
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class SSOFilterIntegratorImpl implements SSOFilterIntegrator
{
   // Key is filter (SSOInterceptor), value is filterMapping
   private final Map<SSOInterceptor, String> ssoInterceptors = new LinkedHashMap<SSOInterceptor, String>();

   private static final Logger log = LoggerFactory.getLogger(SSOFilterIntegratorImpl.class);

   public void addPlugin(ComponentPlugin plugin)
   {
      if (plugin instanceof SSOFilterIntegratorPlugin)
      {
         SSOFilterIntegratorPlugin ssoPlugin = (SSOFilterIntegratorPlugin)plugin;

         if (!ssoPlugin.isEnabled())
         {
            return;
         }

         SSOInterceptor ssoInterceptor = ssoPlugin.getFilter();
         this.ssoInterceptors.put(ssoInterceptor, ssoPlugin.getFilterMapping());

         log.debug("Added new SSOInterceptor " + ssoInterceptor);
      }
   }

   public Map<SSOInterceptor, String> getSSOInterceptors()
   {
      return ssoInterceptors;
   }

}
