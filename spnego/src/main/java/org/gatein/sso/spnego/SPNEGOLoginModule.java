/*
 * JBoss, a division of Red Hat
 * Copyright 2011, Red Hat Middleware, LLC, and individual
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

package org.gatein.sso.spnego;

import org.exoplatform.services.security.jaas.UserPrincipal;
import org.jboss.security.negotiation.common.NegotiationContext;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import java.security.Principal;
import java.util.Map;
import java.util.Set;

/**
 * Modified version of {@link org.jboss.security.negotiation.spnego.SPNEGOLoginModule} customized for portal purposes
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class SPNEGOLoginModule extends org.jboss.security.negotiation.spnego.SPNEGOLoginModule
{
   private String usernamePasswordDomain;

   // TODO: Workaround. Remove once getIdentityFromSubject method will be added to superclass.
   @Override
   public void initialize(final Subject subject, final CallbackHandler callbackHandler, final Map sharedState,
                          final Map options)
   {
      super.initialize(subject, callbackHandler, sharedState, options);
      usernamePasswordDomain = (String) options.get("usernamePasswordDomain");
   }

   // TODO: Workaround. Remove once getIdentityFromSubject method will be added to superclass.
   @Override
   protected Object innerLogin() throws LoginException
   {
      NegotiationContext negotiationContext = NegotiationContext.getCurrentNegotiationContext();

      if (negotiationContext == null)
      {
         if (usernamePasswordDomain == null)
         {
            throw new LoginException("No NegotiationContext and no usernamePasswordDomain defined.");
         }

         return usernamePasswordLogin();
      }
      else
      {
         return super.innerLogin();
      }
   }

   // TODO: Workaround. Remove once getIdentityFromSubject method will be added to superclass.
   private Object usernamePasswordLogin() throws LoginException
   {
      log.debug("Falling back to username/password authentication");

      LoginContext lc = new LoginContext(usernamePasswordDomain, callbackHandler);
      lc.login();

      Subject userSubject = lc.getSubject();

      Principal identity = getIdentityFromSubject(userSubject);
      setIdentity(identity);

      return Boolean.TRUE;
   }


   /**
    * Obtaining identity from subject. We need to find instance of {@link UserPrincipal}
    * , which is added here during FORM authentication.
    * See {@link org.exoplatform.services.security.j2ee.JbossLoginModule#commit()}
    *
    * @param userSubject subject from FORM authentication
    * @return identity
    * @throws javax.security.auth.login.LoginException
    */
   protected Principal getIdentityFromSubject(Subject userSubject) throws LoginException
   {
      Set principals = userSubject.getPrincipals(UserPrincipal.class);
      if (principals.isEmpty())
      {
         throw new LoginException("No UserPrincipals returned after login.");
      }
      else if (principals.size() > 1)
      {
         log.warn("Multiple UserPrincipals returned, using first principal in set.");
      }

	  Principal identity = (Principal) principals.iterator().next();
	  return identity;
   }
}
