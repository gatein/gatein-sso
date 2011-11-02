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

import org.apache.catalina.Realm;
import org.apache.catalina.Session;
import org.apache.catalina.authenticator.AuthenticatorBase;
import org.apache.catalina.authenticator.Constants;
import org.apache.catalina.authenticator.FormAuthenticator;
import org.apache.catalina.authenticator.SavedRequest;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.deploy.LoginConfig;
import org.apache.log4j.Logger;
import org.gatein.sso.agent.filter.SPNEGOFilter;
import org.jboss.security.negotiation.MessageFactory;
import org.jboss.security.negotiation.NegotiationException;
import org.jboss.security.negotiation.NegotiationMessage;
import org.jboss.security.negotiation.common.MessageTrace;
import org.jboss.security.negotiation.common.NegotiationContext;
import org.jboss.util.Base64;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Method;
import java.security.Principal;

import static org.apache.catalina.authenticator.Constants.SESS_PASSWORD_NOTE;
import static org.apache.catalina.authenticator.Constants.SESS_USERNAME_NOTE;
import static org.apache.catalina.authenticator.Constants.FORM_ACTION;
import static org.apache.catalina.authenticator.Constants.FORM_PASSWORD;
import static org.apache.catalina.authenticator.Constants.FORM_PRINCIPAL_NOTE;
import static org.apache.catalina.authenticator.Constants.FORM_USERNAME;

/**
 * An authenticator to manage Negotiation based authentication in connection with the
 * Negotiation login module. It's fork of {@link org.jboss.security.negotiation.NegotiationAuthenticator}, which is here
 * to ensure backwards compatibility with JBoss 5 (jbossWeb 2)
 *
 * @author darran.lofthouse@jboss.com
 * @version $Revision: 110643 $
 */
public class NegotiationAuthenticator extends FormAuthenticator
{

   private static final Logger log = Logger.getLogger(NegotiationAuthenticator.class);

   private static final String NEGOTIATE = "Negotiate";

   private static final String NEGOTIATION_CONTEXT = "NEGOTIATION_CONTEXT";

   private static final String FORM_METHOD = "FORM";

   protected String getNegotiateScheme()
   {
      return NEGOTIATE;
   }

   @Override
   public boolean authenticate(final Request request, final HttpServletResponse response, final LoginConfig config)
         throws IOException
   {

      boolean DEBUG = log.isDebugEnabled();
      log.trace("Authenticating user");

      Principal principal = request.getUserPrincipal();
      if (principal != null)
      {
         if (log.isTraceEnabled())
            log.trace("Already authenticated '" + principal.getName() + "'");
         return true;
      }

      String contextPath = request.getContextPath();
      String requestURI = request.getDecodedRequestURI();
      boolean loginAction = requestURI.startsWith(contextPath) && requestURI.endsWith(FORM_ACTION);
      if (loginAction)
      {
         Realm realm = context.getRealm();
         String username = request.getParameter(FORM_USERNAME);
         String password = request.getParameter(FORM_PASSWORD);
         principal = realm.authenticate(username, password);
         if (principal == null)
         {
            RequestDispatcher disp = context.getServletContext().getRequestDispatcher(config.getErrorPage());
            try
            {
               disp.forward(request.getRequest(), response);
            }
            catch (ServletException e)
            {
               IOException ex = new IOException("Unable to forward to error page.");
               ex.initCause(e);

               throw ex;
            }
            return false;
         }

         Session session = request.getSessionInternal();
         requestURI = savedRequestURL(session);

         session.setNote(FORM_PRINCIPAL_NOTE, principal);
         session.setNote(SESS_USERNAME_NOTE, username);
         session.setNote(SESS_PASSWORD_NOTE, password);

         register(request, response, principal, FORM_METHOD, username, password);
         response.sendRedirect(response.encodeRedirectURL(requestURI));

         return false;
      }

      String negotiateScheme = getNegotiateScheme();

      if (DEBUG)
         log.debug("Header - " + request.getHeader("Authorization"));
      String authHeader = request.getHeader("Authorization");
      if (authHeader == null)
      {

         log.debug("No Authorization Header, initiating negotiation");
         initiateNegotiation(request, response, config);

         return false;
      }
      else if (authHeader.startsWith(negotiateScheme + " ") == false)
      {
         throw new IOException("Invalid 'Authorization' header.");
      }

      String authTokenBase64 = authHeader.substring(negotiateScheme.length() + 1);
      byte[] authToken = Base64.decode(authTokenBase64);
      ByteArrayInputStream authTokenIS = new ByteArrayInputStream(authToken);
      MessageTrace.logRequestBase64(authTokenBase64);
      MessageTrace.logRequestHex(authToken);

      Session session = request.getSessionInternal();
      NegotiationContext negotiationContext = (NegotiationContext) session.getNote(NEGOTIATION_CONTEXT);
      if (negotiationContext == null)
      {
         log.debug("Creating new NegotiationContext");
         negotiationContext = new NegotiationContext();
         session.setNote(NEGOTIATION_CONTEXT, negotiationContext);
      }

      String username = negotiationContext.getUsername();
      if (username == null || username.length() == 0)
      {
         username = session.getId() + "_" + String.valueOf(System.currentTimeMillis());
         negotiationContext.setUsername(username);
      }
      String authenticationMethod = "";
      try
      {
         // Set the ThreadLocal association.
         negotiationContext.associate();

         MessageFactory mf = MessageFactory.newInstance();
         if (mf.accepts(authTokenIS) == false)
         {
            throw new IOException("Unsupported negotiation mechanism.");
         }

         NegotiationMessage requestMessage = mf.createMessage(authTokenIS);
         negotiationContext.setRequestMessage(requestMessage);

         Realm realm = context.getRealm();
         principal = realm.authenticate(username, (String) null);

         authenticationMethod = negotiationContext.getAuthenticationMethod();

         if (DEBUG && principal != null)
            log.debug("authenticated principal = " + principal);

         NegotiationMessage responseMessage = negotiationContext.getResponseMessage();
         if (responseMessage != null)
         {
            ByteArrayOutputStream responseMessageOS = new ByteArrayOutputStream();
            responseMessage.writeTo(responseMessageOS, true);
            String responseHeader = responseMessageOS.toString();

            MessageTrace.logResponseBase64(responseHeader);

            response.setHeader("WWW-Authenticate", negotiateScheme + " " + responseHeader);
         }

      }
      catch (NegotiationException e)
      {
         IOException ioe = new IOException("Error processing " + negotiateScheme + " header.");
         ioe.initCause(e);
         throw ioe;
      }
      finally
      {
         // Clear the headers and remove the ThreadLocal association.
         negotiationContext.clear();
      }

      if (principal == null)
      {
         response.sendError(Response.SC_UNAUTHORIZED);
      }
      else
      {
         register(request, response, principal, authenticationMethod, username, null);
      }

      return (principal != null);
   }

   /**
    * Purpose of this method is backwards compatibility with JBoss 5.1
    *
    * @param request request
    * @param response response
    * @param config login configuration
    * @return result of authentication
    * @throws IOException
    */
   public boolean authenticate(final Request request, final Response response, final LoginConfig config)
         throws IOException
   {
      return authenticate(request, (HttpServletResponse)response, config);
   }

   /**
    * Purpose of this method is backwards compatibility with JBoss 5.1
    *
    * @param request request
    * @param response response
    * @param principal Principal to register
    * @param authType authentication type (FORM, BASIC, SPNEGO, ...)
    * @param username name of user
    * @param password password of user
    *
    */
   protected void register(Request request, HttpServletResponse response,
                           Principal principal, String authType,
                           String username, String password)
   {
      try
      {
         // first trying JBoss 6 signature register(Request, HttpServletResponse, Principal, String, String, String)
         Method registerNewSignature = AuthenticatorBase.class.getDeclaredMethod("register", Request.class, HttpServletResponse.class, Principal.class, String.class, String.class, String.class);

         // We have a method, so calling super
         if (registerNewSignature != null)
         {
            super.register(request, response, principal, authType, username, password);
         }
      }
      catch (NoSuchMethodException nsme)
      {
         // fallback to JBoss 5 signature register(Request, Response, Principal, String, String, String)
         if (log.isDebugEnabled())
         {
            log.debug("Method 'register' with signature register(Request, HttpServletResponse, Principal, String, String, String) not found. Fallback to JBoss 5 signature register(Request, Response, Principal, String, String, String).");
         }
         try
         {
            Method registerOldSignature = AuthenticatorBase.class.getDeclaredMethod("register", Request.class, Response.class, Principal.class, String.class, String.class, String.class);
            registerOldSignature.invoke(this, request, (Response)response, principal, authType, username, password);
         }
         catch (Exception e)
         {
            log.error(e);
         }
      }
      catch (Exception e)
      {
         log.error(e);
      }
   }

    /**
     * Return the request URI (with the corresponding query string, if any)
     * from the saved request so that we can redirect to it. We need to override this method
     * because Constants.FORM_REQUEST_NOTE can be null sometimes (when request was send to /portal/login without displaying login.jsp page)
     *
     * @param session Our current session
     */
    protected String savedRequestURL(Session session)
    {
       String savedURI = super.savedRequestURL(session);

       // use url saved by SPNEGOFilter if saved request not found
       if (savedURI == null)
       {
          savedURI = (String)session.getSession().getAttribute(SPNEGOFilter.ATTR_INITIAL_URI);
       }

       // using default context if nothing helped
       if (savedURI == null)
       {
          savedURI = session.getSession().getServletContext().getContextPath();
       }

       return savedURI;
    }

   private void initiateNegotiation(final Request request, final HttpServletResponse response, final LoginConfig config)
         throws IOException
   {
      String loginPage = config.getLoginPage();
      if (loginPage != null)
      {
         // TODO - Logic to cache and restore request.
         ServletContext servletContext = context.getServletContext();
         RequestDispatcher disp = servletContext.getRequestDispatcher(loginPage);

         try
         {
            Session session = request.getSessionInternal();
            saveRequest(request, session);

            disp.include(request.getRequest(), response);
            response.setHeader("WWW-Authenticate", getNegotiateScheme());
            response.setStatus(Response.SC_UNAUTHORIZED);
         }
         catch (ServletException e)
         {
            IOException ex = new IOException("Unable to include loginPage");
            ex.initCause(e);

            throw ex;
         }

      }
      else
      {
         response.setHeader("WWW-Authenticate", getNegotiateScheme());
         response.sendError(Response.SC_UNAUTHORIZED);
      }

      response.flushBuffer();
   }
}
