/*
 *  JBoss, a division of Red Hat
 *  Copyright 2012, Red Hat Middleware, LLC, and individual contributors as indicated
 *  by the @authors tag. See the copyright.txt in the distribution for a
 *  full listing of individual contributors.
 *
 *  This is free software; you can redistribute it and/or modify it
 *  under the terms of the GNU Lesser General Public License as
 *  published by the Free Software Foundation; either version 2.1 of
 *  the License, or (at your option) any later version.
 *
 *  This software is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this software; if not, write to the Free
 *  Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 *  02110-1301 USA, or see the FSF site: http://www.fsf.org.
 *
 */

package org.gatein.sso.agent.opensso;

/**
 * Encapsulate all important informations from SAML message received from OpenSSO CDCServlet
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
class CDMessageContext
{

   private final Boolean success;
   private final Integer inResponseTo;
   private final String notBefore;
   private final String notOnOrAfter;
   private final String ssoToken;

   public CDMessageContext(Boolean success, Integer inResponseTo, String notBefore,
                           String notOnOrAfter, String ssoToken)
   {
      this.success = success;
      this.inResponseTo = inResponseTo;
      this.notBefore = notBefore;
      this.notOnOrAfter = notOnOrAfter;
      this.ssoToken = ssoToken;
   }

   public Boolean getSuccess()
   {
      return success;
   }

   public Integer getInResponseTo()
   {
      return inResponseTo;
   }

   public String getNotBefore()
   {
      return notBefore;
   }

   public String getNotOnOrAfter()
   {
      return notOnOrAfter;
   }

   public String getSsoToken()
   {
      return ssoToken;
   }

   @Override
   public String toString()
   {
      StringBuilder builder = new StringBuilder("CDMessageContext [ success=");
      builder.append(success).append(", inResponseTo=").append(inResponseTo);
      builder.append(", notBefore=").append(notBefore);
      builder.append(", notOnOrAfter=").append(notOnOrAfter);
      builder.append(", token=").append(ssoToken).append(" ]");
      return builder.toString();
   }
}
