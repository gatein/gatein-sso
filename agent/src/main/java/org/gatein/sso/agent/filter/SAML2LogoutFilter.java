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

import javax.servlet.http.HttpServletRequest;

/**
 * Filter for redirecting GateIn logout request (triggered from GateIn UI by user) to SAML2 global logout request.
 * Filter is usable only if we want to enable SAML2 global logout.
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class SAML2LogoutFilter extends AbstractLogoutFilter
{

   @Override
   protected String getRedirectUrl(HttpServletRequest httpRequest)
   {
      // This could happen if user clicked to "logout" link but session already expired in the meantime
      if (httpRequest.getRemoteUser() == null) {
          return httpRequest.getContextPath();
      }

      String logoutURL =  this.logoutUrl;

      // URL from filter init parameter has priority, but if not provided, we will use SAML global logout.
      // Second condition means that System property was not provided (In this case we also won't use logoutUrl)
      if (logoutURL == null || logoutUrl.startsWith("${"))
      {
         logoutURL = httpRequest.getContextPath() + "/dologin?GLO=true";
      }

      return logoutURL;
   }
}
