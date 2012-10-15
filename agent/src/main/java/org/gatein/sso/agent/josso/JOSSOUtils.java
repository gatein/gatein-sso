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

package org.gatein.sso.agent.josso;

import org.gatein.common.logging.Logger;
import org.gatein.common.logging.LoggerFactory;
import org.josso.agent.AbstractSSOAgent;
import org.josso.agent.Lookup;
import org.josso.agent.SSOPartnerAppConfig;
import org.josso.agent.http.HttpSSOAgent;

import javax.servlet.http.HttpServletRequest;
import java.security.AccessController;
import java.security.PrivilegedAction;

/**
 * Utils for JOSSO
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class JOSSOUtils
{
   private static Logger log = LoggerFactory.getLogger(JOSSOUtils.class);

   private static final String PROPERTY_AGENT_CONFIG_FILE = "gatein.sso.josso.agent.config.file";

   /**
    * Lookup for SSO agent from Spring configuration file
    *
    * @return HttpSSOAgent instance
    */
   public static HttpSSOAgent lookupSSOAgent() throws Exception
   {
      Lookup lookup = Lookup.getInstance();
      String location = getSystemProperty(PROPERTY_AGENT_CONFIG_FILE, "josso-agent-config.xml");
      log.info("Using JOSSO agent from location " + location);
      lookup.init(location);
      return (HttpSSOAgent)lookup.lookupSSOAgent();
   }

   /**
    * Obtain ID of partnerApp from configuration of given jossoAgent and from contextPath of given servlet request
    *
    * @param jossoAgent
    * @param hreq
    * @return partnerApp
    */
   public static String getPartnerAppId(AbstractSSOAgent jossoAgent, HttpServletRequest hreq)
   {
      String requester = null;

      // Try to obtain requester from ID of partnerApp
      SSOPartnerAppConfig partnerAppConfig = jossoAgent.getPartnerAppConfig(hreq.getServerName(), hreq.getContextPath());
      if (partnerAppConfig != null)
      {
         requester = partnerAppConfig.getId();
      }

      // Fallback to contextPath if previous failed
      if (requester == null)
      {
         requester = hreq.getContextPath().substring(1);
      }

      if (log.isTraceEnabled())
      {
         log.trace("Using partnerAppId " + requester);
      }
      return requester;
   }

   public static String getSystemProperty(final String key, final String defaultValue)
   {
      return AccessController.doPrivileged(new PrivilegedAction<String>()
      {
         public String run()
         {
            return System.getProperty(key, defaultValue);
         }
      });
   }
}
