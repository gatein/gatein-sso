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

import org.gatein.common.logging.Logger;
import org.gatein.common.logging.LoggerFactory;
import org.gatein.common.util.Base64;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parsing of SAML message received from OpenSSO CDCServlet
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
class CDMessageParser
{

   private static final Logger log = LoggerFactory.getLogger(CDMessageParser.class);

   private static final Pattern SAML_SUCCESS_PATTERN = Pattern.compile("<samlp:StatusCode Value=(.*)>");
   private static final Pattern SAML_DATE_CONDITIONS = Pattern.compile("<saml:Conditions  NotBefore=\"(.*)\" NotOnOrAfter=\"(.*)\" >");
   private static final Pattern IN_RESPONSE_TO_PATTERN = Pattern.compile("InResponseTo=\"([0-9]*)\"");
   private static final Pattern TOKEN_PATTERN = Pattern.compile("<saml:NameIdentifier .*>(.*)</saml:NameIdentifier>");

   /**
    *
    * @param encodedInputMessage
    * @return decoded and parsed object with all important informations from SAML message
    */
   public CDMessageContext parseMessage(String encodedInputMessage)
   {
      String decodedMessage = decodeMessage(encodedInputMessage);

      if (log.isTraceEnabled())
      {
         log.trace("Decoded message from CDCServlet: ");
         log.trace(decodedMessage);
      }

      boolean success = false;
      Matcher m = SAML_SUCCESS_PATTERN.matcher(decodedMessage);
      if (m.find())
      {
         String group = m.group(1);
         if (group.contains("samlp:Success"))
         {
            success = true;
         }
      }

      String beforeDate = null;
      String afterDate = null;
      m = SAML_DATE_CONDITIONS.matcher(decodedMessage);
      if (m.find())
      {
         beforeDate = m.group(1);
         afterDate = m.group(2);
      }

      Integer inResponseTo = -1;
      m = IN_RESPONSE_TO_PATTERN.matcher(decodedMessage);
      if (m.find())
      {
         inResponseTo = Integer.parseInt(m.group(1));
      }

      String token = null;
      m = TOKEN_PATTERN.matcher(decodedMessage);
      if (m.find())
      {
         token = m.group(1);
      }
      // Token is URL encoded in OpenSSO and we need to decode it (not encoded in OpenAM but we can decode in either case)
      try
      {
         token = URLDecoder.decode(token, "UTF-8");
      }
      catch (UnsupportedEncodingException uee)
      {
         throw new RuntimeException(uee);
      }

      return new CDMessageContext(success, inResponseTo, beforeDate, afterDate, token);
   }

   /**
    * @param encodedInputMessage
    * @return decoded string, which represents SAML message received from CDCServlet
    */
   String decodeMessage(String encodedInputMessage)
   {
      byte[] bytes = Base64.decode(encodedInputMessage);
      String decodedSamlMessage = new String(bytes);
      return decodedSamlMessage;
   }
}
