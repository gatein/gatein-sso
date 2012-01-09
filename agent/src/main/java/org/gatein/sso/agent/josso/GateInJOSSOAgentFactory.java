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
import org.josso.agent.SSOAgentRequest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Abstraction of factory, where concrete implementation of factory can be different for various josso versions.
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public abstract class GateInJOSSOAgentFactory
{
   private static AtomicReference<GateInJOSSOAgentFactory> INSTANCE = new AtomicReference<GateInJOSSOAgentFactory>();

   private static final Logger log = LoggerFactory.getLogger(GateInJOSSOAgentFactory.class);

   public static GateInJOSSOAgentFactory getInstance()
   {
      GateInJOSSOAgentFactory result = INSTANCE.get();
      
      if (result == null)
      {
         INSTANCE.compareAndSet(null, createInstance());
         result = INSTANCE.get();
      }

      return result;
   }

   /**
    * @return Concrete factory, where the factory implementation can be different according to josso version.
    */
   private static GateInJOSSOAgentFactory createInstance()
   {
      try
      {
         Class<?> factoryClass = Thread.currentThread().getContextClassLoader().loadClass("org.gatein.sso.agent.josso.impl.GateInJOSSOAgentFactoryImpl");
         return (GateInJOSSOAgentFactory)factoryClass.newInstance();
      }
      catch (Exception e)
      {
         throw new RuntimeException(e);
      }
   }

   public abstract SSOAgentRequest getSSOAgentRequest(String requester, int action, String sessionId, String assertionId,
                                                      HttpServletRequest hreq, HttpServletResponse hres);


   public abstract GateInAuthenticationDelegate getAuthenticationDelegate();
   

}
