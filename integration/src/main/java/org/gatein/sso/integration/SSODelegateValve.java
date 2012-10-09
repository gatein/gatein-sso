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

import org.apache.catalina.Valve;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.gatein.common.logging.Logger;
import org.gatein.common.logging.LoggerFactory;
import org.jboss.servlet.http.HttpEvent;

import javax.servlet.ServletException;
import java.io.IOException;

/**
 * Delegates work to another valve configured through option 'delegateClass'
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class SSODelegateValve implements Valve
{
   private static final Logger log = LoggerFactory.getLogger(SSODelegateValve.class);

   private Valve delegate;
   private String delegateValveClassName;

   public String getDelegateValve()
   {
      return delegateValveClassName;
   }

   public void setDelegateValve(String delegateValve)
   {
      this.delegateValveClassName = delegateValve;
   }

   public String getInfo()
   {
      Valve delegate = getOrLoadDelegate(delegateValveClassName);
      return delegate.getInfo();
   }

   public Valve getNext()
   {
      Valve delegate = getOrLoadDelegate(delegateValveClassName);
      return delegate.getNext();
   }

   public void setNext(Valve valve)
   {
      Valve delegate = getOrLoadDelegate(delegateValveClassName);
      delegate.setNext(valve);
   }

   public void backgroundProcess()
   {
      Valve delegate = getOrLoadDelegate(delegateValveClassName);
      delegate.backgroundProcess();
   }

   public void invoke(Request request, Response response) throws IOException, ServletException
   {
      Valve delegate = getOrLoadDelegate(delegateValveClassName);
      delegate.invoke(request, response);
   }

   public void event(Request request, Response response, HttpEvent event) throws IOException, ServletException
   {
      Valve delegate = getOrLoadDelegate(delegateValveClassName);
      delegate.event(request, response, event);
   }


   private Valve getOrLoadDelegate(String className)
   {
      if (delegate == null)
      {
         if (className == null)
         {
            throw new IllegalStateException("Delegate className is null in SSODelegateValve");
         }

         Class<Valve> delegateClass = (Class<Valve>)SSOUtils.loadClass(className);
         try
         {
            this.delegate = delegateClass.newInstance();
            if (log.isTraceEnabled())
            {
               log.trace("Delegating valve created successfuly: " + delegate);
            }
         }
         catch (Exception e)
         {
            throw new RuntimeException("Can't instantiate " + delegateClass, e);
         }
      }

      return delegate;
   }
}
