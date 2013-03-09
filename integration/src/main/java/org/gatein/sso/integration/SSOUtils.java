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

import org.gatein.common.logging.Logger;
import org.gatein.common.logging.LoggerFactory;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.StringTokenizer;

/**
 * Helper with various utils
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class SSOUtils
{
   private static final Logger log = LoggerFactory.getLogger(SSOUtils.class);
   private static boolean ssoEnabled;
   private static boolean oauthEnabled;

   static
   {
      String ssoEnabledParam = getSystemProperty("gatein.sso.enabled", "false");
      ssoEnabled = Boolean.parseBoolean(ssoEnabledParam);
      String oauthEnabledParam = getSystemProperty("gatein.oauth.enabled", "false");
      oauthEnabled = Boolean.parseBoolean(oauthEnabledParam);
   }

   public static boolean isSSOEnabled()
   {
      return ssoEnabled;
   }

   public static boolean isOAuthEnabled()
   {
      return oauthEnabled;
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
   public static Class<?> loadClass(final String filterClazz)
   {
      return AccessController.doPrivileged(new PrivilegedAction<Class<?>>()
      {
         public Class<?> run()
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
               return (Class<?>)Class.forName(filterClazz);
            }
            catch (ClassNotFoundException cnfe)
            {
               throw new RuntimeException("Unable to load class " + filterClazz + " with classloaders " +
                     Thread.currentThread().getContextClassLoader() + ", " + SSOUtils.class.getClassLoader() + " and Class.forName", cnfe);
            }
         }
      });
   }

   /**
    * Replaces variables of ${var:default} with System.getProperty(var, default). If no variables are found, returns
    * the same string, otherwise a copy of the string with variables substituted
    *
    * @param input
    * @return A string with vars replaced, or the same string if no vars found
    */
   public static String substituteSystemProperty(String input)
   {
      String output = substituteVariable(input);

      if (log.isTraceEnabled())
      {
         log.trace("Substituting value from configuration with System properties - input=" + input + ", output=" + output);
      }
      return output;
   }

   // Methods for substitute system properties are forked from JGroups class org.jgroups.utils.Util to avoid bugs
   // and ensure same parsing behaviour, which is used by JGroups and by JBoss AS.

   private static String substituteVariable(String val)
   {
      if(val == null)
         return val;
      String retval=val, prev;

      while(retval.contains("${"))
      { // handle multiple variables in val
         prev=retval;
         retval=_substituteVar(retval);
         if(retval.equals(prev))
            break;
      }
      return retval;
   }

   private static String _substituteVar(String val)
   {
      int start_index, end_index;
      start_index=val.indexOf("${");
      if(start_index == -1)
         return val;
      end_index=val.indexOf("}", start_index+2);
      if(end_index == -1)
         throw new IllegalArgumentException("missing \"}\" in " + val);

      String tmp=getProperty(val.substring(start_index +2, end_index));
      if(tmp == null)
         return val;
      StringBuilder sb=new StringBuilder();
      sb.append(val.substring(0, start_index));
      sb.append(tmp);
      sb.append(val.substring(end_index+1));
      return sb.toString();
   }

   private static String getProperty(String s)
   {
      String var, default_val, retval=null;
      int index=s.indexOf(":");
      if(index >= 0)
      {
         var=s.substring(0, index);
         default_val=s.substring(index+1);
         if(default_val != null && default_val.length() > 0)
            default_val=default_val.trim();
         retval=_getProperty(var, default_val);
      }
      else
      {
         var=s;
         retval=_getProperty(var, null);
      }
      return retval;
   }

   /**
    * Parses a var which might be comma delimited, e.g. bla,foo:1000: if 'bla' is set, return its value. Else,
    * if 'foo' is set, return its value, else return "1000"
    * @param var
    * @param default_value
    * @return
    */
   private static String _getProperty(String var, String default_value)
   {
      if(var == null)
         return null;
      List<String> list=parseCommaDelimitedStrings(var);
      if(list == null || list.isEmpty())
      {
         list=new ArrayList<String>(1);
         list.add(var);
      }
      String retval=null;
      for(String prop: list)
      {
         try
         {
            retval= getSystemProperty(prop, null);
            if(retval != null)
               return retval;
         }
         catch(Throwable e)
         {
         }
      }
      return default_value;
   }

   /** e.g. "bela,jeannette,michelle" --> List{"bela", "jeannette", "michelle"} */
   private static List<String> parseCommaDelimitedStrings(String l)
   {
      return parseStringList(l, ",");
   }

   private static List<String> parseStringList(String l, String separator)
   {
      List<String> tmp=new LinkedList<String>();
      StringTokenizer tok=new StringTokenizer(l, separator);
      String t;

      while(tok.hasMoreTokens())
      {
         t=tok.nextToken();
         tmp.add(t.trim());
      }

      return tmp;
   }
}
