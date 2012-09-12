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

   private String gateInHost;
   private String gateInPort;
   private String gateInContext;

   public AbstractIdentityPlugin()
   {
      InputStream is = null;
      try
      {
         // Load the GateIn properties
         Properties properties = new Properties();
         is = loadInputStream();
         properties.load(is);

         this.gateInHost = properties.getProperty("host");
         this.gateInPort = properties.getProperty("port");
         this.gateInContext = properties.getProperty("context");

         log.info("GateIn Host: " + this.gateInHost + ", GateIn Port: " + gateInPort + ", GateIn context: " + gateInContext);
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

   public String getGateInHost()
   {
      return gateInHost;
   }

   public void setGateInHost(String gateInHost)
   {
      this.gateInHost = gateInHost;
   }

   public String getGateInPort()
   {
      return gateInPort;
   }

   public void setGateInPort(String gateInPort)
   {
      this.gateInPort = gateInPort;
   }

   public String getGateInContext()
   {
      return gateInContext;
   }

   public void setGateInContext(String gateInContext)
   {
      this.gateInContext = gateInContext;
   }

   protected String createCallbackURL(String username, String password)
   {
      StringBuilder builder = new StringBuilder("http://");
      builder.append(this.gateInHost).append(":").append(this.gateInPort).append("/")
            .append(this.gateInContext).append("/rest/sso/authcallback/auth/")
            .append(username).append("/").append(password);
      return builder.toString();
   }

   protected boolean bindImpl(String username, String password)
         throws Exception
   {
      log.debug("Performing Authentication........................");
      log.debug("Username: " + username);

      String restCallbackURL = createCallbackURL(username, password);
      boolean success = this.executeRemoteCall(restCallbackURL);

      return success;
   }

   protected boolean executeRemoteCall(String authUrl) throws Exception
   {
      HttpClient client = new HttpClient();
      GetMethod method = null;
      try
      {
         method = new GetMethod(authUrl);

         int status = client.executeMethod(method);
         String response = method.getResponseBodyAsString();

         switch (status)
         {
            case 200:
               if (response.equals(Boolean.TRUE.toString()))
               {
                  return true;
               }
               break;
         }

         return false;
      }
      finally
      {
         if (method != null)
         {
            method.releaseConnection();
         }
      }
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
