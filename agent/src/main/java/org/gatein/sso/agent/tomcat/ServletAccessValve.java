/*
 * JBoss, a division of Red Hat
 * Copyright 2012, Red Hat Middleware, LLC, and individual contributors as indicated
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

package org.gatein.sso.agent.tomcat;

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;
import org.gatein.common.logging.Logger;
import org.gatein.common.logging.LoggerFactory;

import javax.servlet.ServletException;
import java.io.IOException;

/**
 * Valve for adding {@link javax.servlet.http.HttpServletRequest} and {@link javax.servlet.http.HttpServletResponse} into threadLocal
 * so that it can be accessed from Login Modules during authentication.
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class ServletAccessValve extends ValveBase
{
   private static final Logger log = LoggerFactory.getLogger(ServletAccessValve.class);
   
   @Override
   public void invoke(Request request, Response response) throws IOException, ServletException
   {
      ServletAccess.setRequestAndResponse(request, response);
      if (log.isTraceEnabled())
      {
         log.trace("Current HttpServletRequest and HttpServletResponse added to ThreadLocal.");
      }

      try
      {
         getNext().invoke(request, response);
      }
      finally
      {
         ServletAccess.resetRequestAndResponse();
         if (log.isTraceEnabled())
         {
            log.trace("Cleaning ThreadLocal");
         }
      }
   }

}
