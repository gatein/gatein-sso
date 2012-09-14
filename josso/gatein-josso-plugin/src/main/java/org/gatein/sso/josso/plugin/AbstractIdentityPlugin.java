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

package org.gatein.sso.josso.plugin;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.gatein.sso.plugin.RestCallbackCaller;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.util.Properties;

/**
 * Abstract superclass for JOSSO identity plugin
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class AbstractIdentityPlugin
{
   private static final Log log = LogFactory.getLog(AbstractIdentityPlugin.class);
   private static final String PROPERTIES_FILENAME = "gatein.properties";

   private RestCallbackCaller restCallbackCaller;

   public AbstractIdentityPlugin()
   {
      InputStream is = null;
      try
      {
         // Load the GateIn properties
         Properties properties = new Properties();
         is = loadInputStream();
         properties.load(is);

         String gateInHost = properties.getProperty("host");
         String gateInPort = properties.getProperty("port");
         String gateInContext = properties.getProperty("context");
         String gateInProtocol = properties.getProperty("protocol");
         String gateInHttpMethod = properties.getProperty("httpMethod");

         log.debug("GateIn Host: " + gateInHost + ", GateIn Port: " + gateInPort + ", GateIn context: " + gateInContext + ", Protocol=" + gateInProtocol + ", http method=" + gateInHttpMethod);

         this.restCallbackCaller = new RestCallbackCaller(gateInProtocol, gateInHost, gateInPort, gateInContext, gateInHttpMethod);

         log.info("GateIn Identity Plugin successfully started");
      }
      catch (Exception e)
      {
         throw new RuntimeException("GateIn Identity Plugin registration failed....", e);
      }
      finally
      {
         if(is != null)
         {
            try{is.close();}catch(Exception e){}
         }
      }
   }

   protected boolean bindImpl(String username, String password)
         throws Exception
   {
      log.debug("Performing Authentication........................");
      log.debug("Username: " + username);

      boolean success = this.restCallbackCaller.executeRemoteCall(username, password);

      return success;
   }

   protected InputStream loadInputStream() throws FileNotFoundException
   {
      // Try current classloader first
      InputStream is = is = Thread.currentThread().getContextClassLoader().getResourceAsStream(PROPERTIES_FILENAME);
      if (is != null)
      {
         return is;
      }

      // Fallback to path in current dir
      File f = new File(PROPERTIES_FILENAME);
      if (!f.exists())
      {
         // Fallback to configuration folder in JOSSO 2
         f = new File("etc/" + PROPERTIES_FILENAME);
      }

      if (!f.exists())
      {
         throw new FileNotFoundException("File couldn't be loaded from resources of current classloader and also not available on path " + f.getAbsolutePath());
      }

      return new FileInputStream(f);
   }
}
