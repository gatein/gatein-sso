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

package org.gatein.sso.plugin;

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Object, which runs on SSO server side (JOSSO, CAS, OpenAM) and is used to help with connection to GateIn via REST
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class RestCallbackCaller
{
   private static final Log log = LogFactory.getLog(RestCallbackCaller.class);

   private static final String ENCODING_CHARSET = "UTF-8";

   // If true, we use "https". If false, we use "http"
   private final String protocol;

   // Host (Something like "localhost")
   private final String host;

   // Port (Something like "8080")
   private final String port;

   // Something like "portal"
   private final String pathContext;

   // If true we use "POST" method. If false we use "GET" method
   private final boolean isPostHttpMethod;

   public RestCallbackCaller(String protocol,
                             String host,
                             String port,
                             String pathContext,
                             String httpMethod)
   {
      if (host == null || port == null || pathContext == null)
      {
         throw new IllegalArgumentException("Host, port and context are mandatory, but some of them is not available in configuration. host="
               + host + ", port=" + port + ", context=" + pathContext);
      }

      this.host = host;
      this.port = port;
      this.pathContext = pathContext;

      // Default to GET method if not provided
      if (httpMethod == null || "GET".equalsIgnoreCase(httpMethod))
      {
         isPostHttpMethod = false;
      }
      else if ("POST".equalsIgnoreCase(httpMethod))
      {
         isPostHttpMethod = true;
      }
      else
      {
         throw new IllegalArgumentException("Illegal httpMethod: " + httpMethod + ". Only GET or POST are allowed");
      }

      // Default to http if not provided
      if (protocol == null)
      {
         protocol = "http";
      }
      this.protocol = protocol;


      log.info("RestCallbackCaller initialized: " + this);
   }

   public boolean executeRemoteCall(String username, String password) throws Exception
   {
      try
      {
         HttpResponseContext httpResponse = sendPortalCallbackRequest(username, password);

         int status = httpResponse.getResponseCode();
         String response = httpResponse.getResponse();

         switch (status)
         {
            case 200:
               if (response.equals(Boolean.TRUE.toString()))
               {
                  if (log.isTraceEnabled())
                  {
                     log.trace("User " + username + " authenticated successfully via Rest callback!");
                  }
                  return true;
               }
               break;
         }

         log.debug("Authentication failed for user " + username + ". HTTP status: " + status + ", HTTP response: " + response);
         return false;
      }
      catch (Exception e)
      {
         log.warn("Can't authenticate because of error: " + e.getMessage());
         e.printStackTrace();
         throw e;
      }
   }

   private HttpResponseContext sendPortalCallbackRequest(String username, String password) throws IOException
   {
      String requestURL = null;
      String queryString = null;

      if (isPostHttpMethod)
      {
         StringBuilder builder = new StringBuilder(this.protocol).append("://");
         builder.append(this.host).append(":").append(this.port);

         // Don't append portal context for now. We need the request to be served by rest.war application on portal side
         // because here we can't call request.getParameter("something") before request is processed by RestServlet
         // builder.append("/").append(this.pathContext)
         builder.append("/rest/sso/authcallback/postauth/");

         requestURL = builder.toString();

         queryString = new StringBuilder("username=")
                 .append(URLEncoder.encode(username, ENCODING_CHARSET))
                 .append("&password=")
                 .append(URLEncoder.encode(password, ENCODING_CHARSET))
                 .toString();
      }
      else
      {
         StringBuilder builder = new StringBuilder(this.protocol).append("://");
         builder.append(this.host).append(":").append(this.port).append("/")
               .append(this.pathContext).append("/rest/sso/authcallback/auth/")
               .append(URLEncoder.encode(username, ENCODING_CHARSET))
               .append("/")
               .append(URLEncoder.encode(password, ENCODING_CHARSET));
         requestURL =  builder.toString();
      }

      if (log.isTraceEnabled())
      {
         log.trace("Rest callback URL: " + requestURL + ", query string: " + queryString + ", isPostMethod: " + isPostHttpMethod);
      }

      return sendHttpRequest(requestURL, queryString);
   }

    private HttpResponseContext sendHttpRequest(String url, String urlParameters) throws IOException
    {
        Reader reader = null;
        DataOutputStream wr = null;
        StringBuilder result = new StringBuilder();

        try
        {
            HttpURLConnection connection;

            if (isPostHttpMethod)
            {
                URL tempURL = new URL(url);
                connection = (HttpURLConnection)tempURL.openConnection();
                connection.setRequestMethod("POST");
                connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
                connection.setRequestProperty("Content-Length", "" + Integer.toString(urlParameters.getBytes().length));
            }
            else
            {
                if (urlParameters != null)
                {
                   url = url + "?" + urlParameters;
                }

                URL tempURL = new URL(url);
                connection = (HttpURLConnection)tempURL.openConnection();
            }

            connection.setUseCaches (false);
            connection.setDoInput(true);

            if (isPostHttpMethod)
            {
                connection.setDoOutput(true);

                //Send request
                wr = new DataOutputStream(connection.getOutputStream ());
                wr.writeBytes(urlParameters);
                wr.flush();
            }

            int statusCode = connection.getResponseCode();

            try
            {
                reader = new InputStreamReader(connection.getInputStream());
            }
            catch (IOException ioe)
            {
                reader = new InputStreamReader(connection.getErrorStream());
            }

            char[] buffer = new char[50];
            int nrOfChars;
            while ((nrOfChars = reader.read(buffer)) != -1)
            {
                result.append(buffer, 0, nrOfChars);
            }

            String response = result.toString();
            return new HttpResponseContext(statusCode, response);
        }
        finally
        {
            if (reader != null)
            {
                reader.close();
            }
            if (wr != null) {
                wr.close();
            }
        }
    }


   @Override
   public String toString()
   {
      StringBuilder builder = new StringBuilder("RestCallbackCaller [ protocol=").append(protocol)
            .append(", host=").append(host)
            .append(", port=").append(port)
            .append(", pathContext=").append(pathContext)
            .append(", isPostMethod=").append(isPostHttpMethod)
            .append(" ]");

      return builder.toString();
   }
}
