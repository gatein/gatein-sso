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

package org.gatein.sso.agent.filter;

import org.gatein.common.logging.Logger;
import org.gatein.common.logging.LoggerFactory;
import org.gatein.sso.agent.opensso.OpenSSOAgentImpl;

import javax.servlet.http.HttpServletRequest;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.Random;

/**
 * Filter is used for redirection to OpenSSO CDCServlet. It is intended to be used in Cross-Domain authentication scenario
 * when GateIn and OpenSSO servers are in different DNS domains.
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class OpenSSOCDLoginRedirectFilter extends LoginRedirectFilter
{
   private static final Logger log = LoggerFactory.getLogger(OpenSSOCDLoginRedirectFilter.class);

   private String openSSORealm;
   private String agentUrl;

   private Random random = new Random();
   private SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd", new Locale("en"));
   private SimpleDateFormat timeFormat = new SimpleDateFormat("HH:mm:ss", new Locale("en"));

   @Override
   public void initImpl()
   {
      super.initImpl();

      this.openSSORealm = getInitParameter("OpenSSORealm");
      this.agentUrl = getInitParameter("AgentUrl");
      log.info("Filter configuration: loginUrl=" + loginUrl +
               ", openSSORealm=" + openSSORealm +
               ", agentUrl=" + agentUrl);
   }

   /**
    * Constructs URL for redirection to OpenSSO CDCServlet.
    * It will be something like:
    * http://localhost:8888/opensso/cdcservlet?realm=gatein&goto=http://opensso.local.network:8080/portal/initiatessologin&
    * ProviderID=http://opensso.local.network:8080/portal/initiatessologin/?Realm=ggatein
    * &RequestID=124&IssueInstant=2012-04-10T23:28:50Z&MajorVersion=1&MinorVersion=0
    *
    * @return url for redirection
    */
   @Override
   protected String getLoginRedirectURL(HttpServletRequest httpRequest)
   {
      try
      {
         StringBuilder urlBuilder = new StringBuilder(loginUrl);
         urlBuilder.append("?realm=").append(openSSORealm);
         urlBuilder.append("&goto=").append(URLEncoder.encode(agentUrl, "UTF-8"));

         // We need to use Realm=g because of bug (or strange behaviour) of OpenAM, which cuts first character of realmName during parsing
         // Update GTNSSO-28 - This extra char is supposed to be a "slash" on pre-10.1 versions. So, adding the "g"
         // is not really appropriate. Replacing the "g" with "/" makes it work for both 9.x up to 12.0 (latest tested).
         String providerId = agentUrl + "/?Realm=" + URLEncoder.encode("/" + openSSORealm, "UTF-8");
         urlBuilder.append("&ProviderID=").append(URLEncoder.encode(providerId, "UTF-8"));

         // Generate random number for parameter "inResponseTo" and save it to session. This ID must be in response message in parameter "inResponseTo"
         int requestId = random.nextInt(100000) + 1;
         urlBuilder.append("&RequestID=").append(requestId);
         httpRequest.getSession().setAttribute(OpenSSOAgentImpl.IN_RESPONSE_TO_ATTR, requestId);

         String issueInstant = getFormattedDate();
         urlBuilder.append("&IssueInstant=" + URLEncoder.encode(issueInstant, "UTF-8"));

         urlBuilder.append("&MajorVersion=1&MinorVersion=0");

         String urlToRedirect = urlBuilder.toString();

         if (log.isTraceEnabled())
         {
            log.trace("URL for redirection to CDCServlet: " + urlToRedirect);
         }

         return urlToRedirect;
      }
      catch (UnsupportedEncodingException uee)
      {
         throw new RuntimeException(uee);
      }

   }

   private String getFormattedDate()
   {
      Date d = new Date();
      return dateFormat.format(d) + "T" + timeFormat.format(d) + "Z";
   }

}
