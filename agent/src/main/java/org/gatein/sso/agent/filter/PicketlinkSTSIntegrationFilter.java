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

package org.gatein.sso.agent.filter;

import org.exoplatform.container.web.AbstractFilter;
import org.exoplatform.services.security.jaas.UserPrincipal;
import org.gatein.common.logging.Logger;
import org.gatein.common.logging.LoggerFactory;
import org.jboss.security.SecurityContext;
import org.jboss.security.SecurityContextAssociation;
import org.jboss.security.client.SecurityClient;
import org.jboss.security.client.SecurityClientFactory;
import org.picketlink.identity.federation.core.wstrust.SamlCredential;

import javax.security.auth.Subject;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Set;

/**
 * Filter for set {@link SamlCredential} into {@link SecurityClient}, which enables to propagate authentication from SAML2 ticket into
 * underlying EJB or WS calls.
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class PicketlinkSTSIntegrationFilter extends AbstractFilter
{
   private static Logger log = LoggerFactory.getLogger(PicketlinkSTSIntegrationFilter.class);
   
   public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException
   {
      HttpServletRequest httpRequest = (HttpServletRequest)request;
      if (httpRequest.getRemoteUser() != null)
      {
         try
         {
            SamlCredential samlCredential = getSamlCredential();

            if (log.isTraceEnabled())
            {
               log.trace("Found SamlCredential inside Subject: " + samlCredential);
            }

            // Now set the security context, which can be used in EJB or other calls
            if (samlCredential != null)
            {
               SecurityClient client = SecurityClientFactory.getSecurityClient();
               // Simple login just updates the security context
               client.setSimple(new UserPrincipal(httpRequest.getRemoteUser()), samlCredential);
               client.login();

               if (log.isTraceEnabled())
               {
                  log.trace("SecurityClient successfully updated with SAMLCredential");
               }
            }

         }
         catch (Exception e)
         {
            e.printStackTrace();
         }
      }
      
      chain.doFilter(request, response);
   }

   public void destroy()
   {      
   }

   private SamlCredential getSamlCredential()
   {      
      Subject subj = getCurrentSubject();
      
      if (log.isTraceEnabled())
      {
         log.trace("Found subject " + subj);
      }
      
      if (subj == null)
      {
         return null;
      }
      
      Set<Object> credentials = subj.getPublicCredentials();
      for (Object credential : credentials)
      {
         if (credential instanceof SamlCredential)
         {
            return (SamlCredential)credential;
         }
      }

      return null;
   }

   /**
    * JBoss specific way for obtaining a Subject.
    * TODO: is JBoss specific way needed? subject should be available in ConversationState
    *
    * @return subject
    */
   protected Subject getCurrentSubject()
   {
      SecurityContext securityContext = AccessController.doPrivileged(new PrivilegedAction<SecurityContext>()
      {
         public SecurityContext run()
         {
            return SecurityContextAssociation.getSecurityContext();
         }
      });
      return securityContext.getSubjectInfo().getAuthenticatedSubject();
   }
}
