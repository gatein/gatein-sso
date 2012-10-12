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

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Delegates work to another login module configured through option 'delegateClassName'
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class SSODelegateLoginModule implements LoginModule
{
   private static final String OPTION_DELEGATE_CLASSNAME = "delegateClassName";
   private static final String OPTION_ENABLED = "enabled";

   private static final ConcurrentMap<String, Class<LoginModule>> delegateClasses = new ConcurrentHashMap<String, Class<LoginModule>>();
   private static final Logger log = LoggerFactory.getLogger(SSODelegateLoginModule.class);

   private LoginModule delegate;
   private boolean enabled;

   private static Class<LoginModule> getOrLoadDelegateClass(String className)
   {
      Class<LoginModule> clazz = delegateClasses.get(className);
      if (clazz == null)
      {
         clazz = (Class<LoginModule>)SSOUtils.loadClass(className);
         delegateClasses.putIfAbsent(className, clazz);
         log.debug("Class " + className + " loaded successfuly");
      }

      return clazz;
   }

   public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState, Map<String, ?> options)
   {
      String enabledParam = (String)options.get(OPTION_ENABLED);
      enabledParam = SSOUtils.substituteSystemProperty(enabledParam);
      this.enabled = Boolean.parseBoolean(enabledParam);
      if (!this.enabled)
      {
         if (log.isTraceEnabled())
         {
            log.trace("SSO is disabled. Ignore login module");
         }
         return;
      }

      String delegateClazz = (String)options.get(OPTION_DELEGATE_CLASSNAME);
      delegateClazz = SSOUtils.substituteSystemProperty(delegateClazz);
      if (delegateClazz == null)
      {
         throw new IllegalArgumentException("Option '" + OPTION_DELEGATE_CLASSNAME + "' is not available");
      }
      Class<LoginModule> delegateClass = getOrLoadDelegateClass(delegateClazz);

      try
      {
         this.delegate = delegateClass.newInstance();
         if (log.isTraceEnabled())
         {
            log.trace("Delegating login module created successfuly: " + delegate);
         }
      }
      catch (Exception e)
      {
         throw new RuntimeException("Can't instantiate " + delegateClass, e);
      }

      // Remove options for 'delegateClassName' and 'enabled' to be passed to delegate
      options = removeUnneededOptions(options);

      // Finally invoke method on delegate
      delegate.initialize(subject, callbackHandler, sharedState, options);
   }

   private Map<String, ?> removeUnneededOptions(Map<String, ?> oldMap)
   {
      Map<String, Object> newMap = new HashMap<String, Object>();
      newMap.putAll(oldMap);
      newMap.remove(OPTION_DELEGATE_CLASSNAME);
      newMap.remove(OPTION_ENABLED);
      return newMap;
   }

   public boolean login() throws LoginException
   {
      return enabled ? delegate.login() : false;
   }

   public boolean commit() throws LoginException
   {
      return enabled ? delegate.commit() : false;
   }

   public boolean abort() throws LoginException
   {
      return enabled ? delegate.abort() : false;
   }

   public boolean logout() throws LoginException
   {
      return enabled ? delegate.logout() : false;
   }
}
