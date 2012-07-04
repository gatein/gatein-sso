/*
* JBoss, a division of Red Hat
* Copyright 2006, Red Hat Middleware, LLC, and individual contributors as indicated
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
package org.gatein.sso.authentication.callback;

import javax.security.auth.login.LoginException;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import org.exoplatform.container.ExoContainer;
import org.exoplatform.container.ExoContainerContext;
import org.exoplatform.container.RootContainer;

import org.exoplatform.services.security.Authenticator;
import org.exoplatform.services.security.Credential;
import org.exoplatform.services.security.Identity;
import org.exoplatform.services.security.PasswordCredential;
import org.exoplatform.services.security.UsernameCredential;

import org.exoplatform.services.rest.resource.ResourceContainer;
import org.gatein.common.logging.Logger;
import org.gatein.common.logging.LoggerFactory;

import java.util.Collection;

/**
 * This is a RESTful component that is invoked by central SSO servers like CAS server, JOSSO server etc, to invoke
 * Gatein authentication related queries during their own "Authentication process"
 * 
 * 
 * @author <a href="mailto:sshah@redhat.com">Sohil Shah</a>
 */
@Path("/sso/authcallback")
public class AuthenticationHandler implements ResourceContainer
{
   private static final Logger log = LoggerFactory.getLogger(AuthenticationHandler.class);
	
	 @GET
	 @Path("/auth/{1}/{2}")
   @Produces(
   {MediaType.TEXT_PLAIN})
   public String authenticate(@PathParam("1") String username, @PathParam("2") String password)
   {
		 try
		 {
			  log.debug("---------------------------------------");
			  log.debug("Username: "+username);
			  log.debug("Password: XXXXXXXXXXXXXXXX");

			  Authenticator authenticator = (Authenticator) getContainer().getComponentInstanceOfType(Authenticator.class);
			  			  
			  Credential[] credentials = new Credential[] { new UsernameCredential(username),
          new PasswordCredential(password) };			  			  

			  try
			  {
			  	authenticator.validateUser(credentials);
			  	return ""+Boolean.TRUE;
			  }
			  catch(LoginException le)
			  {
			  	return ""+Boolean.FALSE;
			  }			  			  			  			  
		 }
		 catch(Exception e)
		 {
			 log.error(this, e);
			 throw new RuntimeException(e);
		 }
   }

   /**
    * Obtain list of JAAS roles for some user. For example, for user root it can return String like: "users,administrators,organization"
    * It's usually not needed because SSO authorization is done on portal side, but may be useful for some SSO implementations to use
    * this callback and ask portal for roles.
    *
    * @param username
    * @return {@link String} with roles in format like: "users,administrators,organization"
    */
   @GET
   @Path("/roles/{1}")
   @Produces({MediaType.TEXT_PLAIN})
   public String getJAASRoles(@PathParam("1") String username)
   {      
      try
      {
         log.debug("---------------------------------------");
         log.debug("Going to obtain roles for user: " + username);

         Authenticator authenticator = (Authenticator) getContainer().getComponentInstanceOfType(Authenticator.class);
         Identity identity = authenticator.createIdentity(username);
         Collection<String> roles = identity.getRoles();
         
         StringBuilder result = null;
         for (String role : roles)
         {
            if (result == null)
            {
               result = new StringBuilder(role);
            }
            else
            {
               result.append(",").append(role);
            }
         }
         
         if (result != null)
         {
            return result.toString();
         }
         else
         {
            return "";
         }
      }
      catch(Exception e)
      {
         log.error(this, e);
         throw new RuntimeException(e);
      }
   }
	 
	 private ExoContainer getContainer() throws Exception 
	 {
    ExoContainer container = ExoContainerContext.getCurrentContainer();
    if (container instanceof RootContainer) 
    {
      container = RootContainer.getInstance().getPortalContainer("portal");
    }
    return container;
  }
}
