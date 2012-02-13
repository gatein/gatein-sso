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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class ServletAccess
{
   
   private static ThreadLocal<Holder> holderThreadLocal = new ThreadLocal<Holder>();

   public static void setRequestAndResponse(HttpServletRequest request, HttpServletResponse response)
   {
      holderThreadLocal.set(new Holder(request, response));
   }
   
   public static void resetRequestAndResponse()
   {
      holderThreadLocal.set(null);
   }
   
   public static HttpServletRequest getRequest()
   {
      Holder holder = holderThreadLocal.get();
      if (holder != null)
      {
         return holder.servletRequest;
      }

      return null;
   }

   public static HttpServletResponse getResponse()
   {
      Holder holder = holderThreadLocal.get();
      if (holder != null)
      {
         return holder.servletResponse;
      }

      return null;
   }
   
   private static class Holder
   {
      private final HttpServletRequest servletRequest;
      private final HttpServletResponse servletResponse;
      
      private Holder(HttpServletRequest servletRequest, HttpServletResponse servletResponse)
      {
         this.servletRequest = servletRequest;
         this.servletResponse = servletResponse;
      }
   }
}
