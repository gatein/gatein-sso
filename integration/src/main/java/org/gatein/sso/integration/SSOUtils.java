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

import org.gatein.sso.agent.filter.api.SSOInterceptor;

import java.security.AccessController;
import java.security.PrivilegedAction;

/**
 * Helper with various utils
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class SSOUtils
{
   private static boolean ssoEnabled;

   static
   {
      String ssoEnabledParam = getSystemProperty("gatein.sso.enabled", "false");
      ssoEnabled = Boolean.parseBoolean(ssoEnabledParam);
   }

   public static boolean isSSOEnabled()
   {
      return ssoEnabled;
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

   /**
    * Attempt to load class from various available classloaders
    *
    * @param filterClazz class
    * @return loaded Class
    */
   public static Class<SSOInterceptor> loadClass(String filterClazz)
   {
      Class clazz;

      // Try tccl first
      try
      {
         clazz = Thread.currentThread().getContextClassLoader().loadClass(filterClazz);
         if (clazz != null)
         {
            return clazz;
         }
      }
      catch (ClassNotFoundException cnfe)
      {
      }

      // Fallback to classloader of this class
      try
      {
         clazz = SSOUtils.class.getClassLoader().loadClass(filterClazz);
         if (clazz != null)
         {
            return clazz;
         }
      }
      catch (ClassNotFoundException cnfe)
      {
      }

      try
      {
         return (Class<SSOInterceptor>)Class.forName(filterClazz);
      }
      catch (ClassNotFoundException cnfe)
      {
         throw new RuntimeException("Unable to load class " + filterClazz + " with classloaders " +
               Thread.currentThread().getContextClassLoader() + ", " + SSOUtils.class.getClassLoader() + " and Class.forName", cnfe);
      }
   }
}
