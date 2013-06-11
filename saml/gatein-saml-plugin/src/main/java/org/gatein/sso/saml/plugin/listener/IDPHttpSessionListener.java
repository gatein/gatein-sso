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

package org.gatein.sso.saml.plugin.listener;

import org.gatein.common.logging.Logger;
import org.gatein.common.logging.LoggerFactory;
import org.gatein.sso.integration.SSOUtils;

import javax.servlet.http.HttpSessionEvent;
import javax.servlet.http.HttpSessionListener;

/**
 * Class exists to avoid dependency on picketlink module from gatein.ear and use it only during SAML2 setup
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class IDPHttpSessionListener implements HttpSessionListener
{
   private static final Logger log = LoggerFactory.getLogger(IDPHttpSessionListener.class);

   private static final String PROPERTY_IDP_ENABLED = "gatein.sso.idp.listener.enabled";

   private volatile HttpSessionListener delegate;

   public void sessionDestroyed(HttpSessionEvent se)
   {
      if ("true".equals(SSOUtils.getSystemProperty(PROPERTY_IDP_ENABLED, "false")))
      {
         HttpSessionListener delegate = getOrInitDelegate();
         delegate.sessionDestroyed(se);
      }
      else
      {
         if (log.isTraceEnabled())
         {
            log.trace("Portal is not acting as SAML2 IDP. Ignore this listener");
         }
      }
   }

   public void sessionCreated(HttpSessionEvent se)
   {
   }

   private HttpSessionListener getOrInitDelegate()
   {
      if (delegate == null)
      {
         synchronized (this)
         {
            if (delegate == null)
            {
               delegate = new org.picketlink.identity.federation.web.listeners.IDPHttpSessionListener();
            }
         }
      }

      return delegate;
   }
}
