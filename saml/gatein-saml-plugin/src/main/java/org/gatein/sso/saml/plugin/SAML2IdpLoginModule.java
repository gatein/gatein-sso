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

package org.gatein.sso.saml.plugin;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.BasicResponseHandler;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.util.EntityUtils;
import org.apache.log4j.Logger;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import java.security.Principal;
import java.security.acl.Group;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Login module, which can be executed on SAML Identity provider side. It executes REST requests to GateIn to verify authentication of single user
 * against GateIn or obtain list of roles from GateIn.
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class SAML2IdpLoginModule implements LoginModule
{
   // This option can have two values: "STATIC" or "PORTAL_CALLBACK"
   // "STATIC" means that roles of authenticated user will be statically obtained from "staticRolesList", which means that all users will have same list of roles.
   // "PORTAL_CALLBACK" means that roles will be obtained from GateIn via callback request to GateIn REST service
   private static final String OPTION_ROLES_PROCESSING = "rolesProcessing";

   // This option is valid only if rolesProcessing is STATIC. It contains list of static roles, which will be assigned to each authenticated user.
   private static final String OPTION_STATIC_ROLES_LIST = "staticRolesList";

   //  gateIn URL related property, which will be used to send REST callback requests
   private static final String OPTION_GATEIN_URL = "gateInURL";

   private static Logger log = Logger.getLogger(SAML2IdpLoginModule.class);

   private Subject subject;
   private CallbackHandler callbackHandler;

   @SuppressWarnings("unchecked")
   private Map sharedState;
   
   @SuppressWarnings("unchecked")
   private Map options;

   private String gateInURL;

   private ROLES_PROCESSING_TYPE rolesProcessingType;
   private List<String> staticRolesList;
   
   
   public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState, Map<String, ?> options)
   {
      this.subject = subject;
      this.callbackHandler = callbackHandler;
      this.sharedState = sharedState;
      this.options = options;
      
      // Read options for this login module
      String rolesProcessingType = readOption(OPTION_ROLES_PROCESSING, "STATIC");
      if ("STATIC".equals(rolesProcessingType) || "PORTAL_CALLBACK".equals(rolesProcessingType))
      {
         this.rolesProcessingType = ROLES_PROCESSING_TYPE.valueOf(rolesProcessingType);
      }
      else
      {
         this.rolesProcessingType = ROLES_PROCESSING_TYPE.STATIC;
      }

      String staticRoles = readOption(OPTION_STATIC_ROLES_LIST, "users");
      this.staticRolesList = Arrays.asList(staticRoles.split(","));

      this.gateInURL = readOption(OPTION_GATEIN_URL, "http://localhost:8080/portal");
   }   

   public boolean login() throws LoginException
   {
      try
      {
         Callback[] callbacks = new Callback[2];
         callbacks[0] = new NameCallback("Username");
         callbacks[1] = new PasswordCallback("Password", false);

         callbackHandler.handle(callbacks);
         String username = ((NameCallback)callbacks[0]).getName();
         String password = new String(((PasswordCallback)callbacks[1]).getPassword());
         ((PasswordCallback)callbacks[1]).clearPassword();
         if (username == null || password == null)
         {
            return false;
         }
         
         boolean authenticationSuccess = validateUser(username, password);
         
         if (authenticationSuccess)
         {
            log.debug("Successful REST login request for authentication of user " + username);
            sharedState.put("javax.security.auth.login.name", username);
            return true;
         }
         else
         {
            String message = "Remote login via REST failed for username " + username;
            log.warn(message);
            throw new LoginException(message);
         }
      }
      catch (LoginException le)
      {
         throw le;
      }
      catch (Exception e)
      {
         log.warn("Exception during login: " + e.getMessage(), e);
         throw new LoginException(e.getMessage());
      }
   }

   public boolean commit() throws LoginException
   {
      String username = (String)sharedState.get("javax.security.auth.login.name");

      Set<Principal> principals = subject.getPrincipals();

      Group roleGroup = new SimpleGroup("Roles");
      for (String role : getRoles(username))
      {
         roleGroup.addMember(new SimplePrincipal(role));
      }

      // group principal
      principals.add(roleGroup);

      // username principal
      principals.add(new SimplePrincipal(username));

      return true;
   }

   public boolean abort() throws LoginException
   {
      return true;
   }

   public boolean logout() throws LoginException
   {
      // Remove all principals from Subject
      Set<Principal> principals = new HashSet(subject.getPrincipals());
      for (Principal p : principals)
      {
         subject.getPrincipals().remove(p);
      }

      return true;
   }


   // ********** PROTECTED HELPER METHODS ****************************   

   // TODO: use common-plugin
   protected boolean validateUser(String username, String password)
   {
      StringBuilder urlBuffer = new StringBuilder();
      urlBuffer.append(this.gateInURL
            + "/rest/sso/authcallback/auth/" + username + "/" + password);
      String url = urlBuffer.toString();
      log.debug("Execute callback HTTP for authentication of user: " + username);

      ResponseContext responseContext = this.executeRemoteCall(urlBuffer.toString()); 
      
      return responseContext.status == 200 && "true".equals(responseContext.response.trim());
   }
   
   protected Collection<String> getRoles(String username)
   {
      if (rolesProcessingType == ROLES_PROCESSING_TYPE.STATIC)
      {
         return staticRolesList;
      }
      else
      {
         // We need to execute REST callback to GateIn to ask for roles
         StringBuilder urlBuffer = new StringBuilder();
         urlBuffer.append(this.gateInURL
               + "/rest/sso/authcallback/roles/" + username);
         
         String url = urlBuffer.toString();
       
         log.debug("Execute callback HTTP request: " + url);
         ResponseContext responseContext = this.executeRemoteCall(url);
         
         if (responseContext.status == 200)
         {
            String rolesString = responseContext.response;            
            
            String[] roles = rolesString.split(",");
            return Arrays.asList(roles);
         }
         else
         {
            log.warn("Incorrect response received from REST callback for roles. Status=" + responseContext.status + ", Response=" + responseContext.response);
            return new ArrayList<String>();
         }
      }
   }

   // ********** PRIVATE HELPER METHODS ****************************   
   
   private String readOption(String key, String defaultValue)
   {
      String result = (String)options.get(key);
      if (result == null)
      {
         result = defaultValue;
      }

      if (log.isTraceEnabled())
      {
         log.trace("Read option " + key + "=" + result);
      }

      return result;
   }   

   private ResponseContext executeRemoteCall(String authUrl)
   {
      DefaultHttpClient client = new DefaultHttpClient();
      HttpGet method;

      try
      {
         method = new HttpGet(authUrl);
         HttpResponse httpResponse = client.execute(method);

         int status = httpResponse.getStatusLine().getStatusCode();
         HttpEntity entity = httpResponse.getEntity();
         String response = entity == null ? null : EntityUtils.toString(entity);

         if (log.isTraceEnabled())
         {
            log.trace("Received response from REST call: status=" + status + ", response=" + response);
         }
         
         return new ResponseContext(status, response);         
      }
      catch (Exception e)
      {                  
         log.warn("Error when sending request through HTTP client", e);         
         return new ResponseContext(1000, e.getMessage());
      }
      finally
      {
         client.getConnectionManager().shutdown();
      }
   }

   private static class ResponseContext
   {
      private final int status;
      private final String response;

      private ResponseContext(int status, String response)
      {
         this.status = status;
         this.response = response;
      }
   }
   
   private static enum ROLES_PROCESSING_TYPE
   {
      STATIC,
      PORTAL_CALLBACK
   }
}
