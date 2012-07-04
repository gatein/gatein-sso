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

package org.gatein.sso.saml.plugin.valve;


import org.apache.catalina.Context;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.Session;
import org.apache.catalina.authenticator.Constants;
import org.apache.log4j.Logger;
import org.picketlink.identity.federation.bindings.tomcat.idp.AbstractIDPValve;
import org.picketlink.identity.federation.bindings.tomcat.idp.IDPWebBrowserSSOValve;
import org.picketlink.identity.federation.core.interfaces.TrustKeyManager;
import org.picketlink.identity.federation.core.saml.v1.SAML11Constants;
import org.picketlink.identity.federation.core.saml.v2.constants.JBossSAMLURIConstants;
import org.picketlink.identity.federation.core.util.StringUtil;
import org.picketlink.identity.federation.web.constants.GeneralConstants;
import org.picketlink.identity.federation.web.util.IDPWebRequestUtil;
import org.picketlink.identity.federation.web.util.RedirectBindingUtil;
import org.w3c.dom.Document;

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.lang.reflect.Field;
import java.security.GeneralSecurityException;
import java.security.Principal;

/**
 * Modified version of {@link IDPWebBrowserSSOValve} for GateIn portal purposes.
 * It is used in scenario with GateIn as SAML Identity Provider.
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class PortalIDPWebBrowserSSOValve extends IDPWebBrowserSSOValve
{

   private static final Logger log = Logger.getLogger(PortalIDPWebBrowserSSOValve.class);
   private static final boolean trace = log.isTraceEnabled();

   private static final String REQUEST_FROM_SP = "requestFromSP";
   private static final String REQUEST_FROM_SP_METHOD = "requestFromSPMethod";

   private Context context = null;
   private TrustKeyManager keyManager;

   /**
    * Defines whether we should forward to URL "/hosted" when no SAMLRequest or SAMLResponse are found.
    */
   private Boolean skipForwardingToHostedURL = true;


   public void setSkipForwardingToHostedURL(Boolean skipForwardingToHostedURL)
   {
      this.skipForwardingToHostedURL = skipForwardingToHostedURL;
   }


   @Override
   public void invoke(Request request, Response response) throws IOException, ServletException
   {
      boolean valveInvocationPerformed = false;

      String referer = request.getHeader("Referer");
      String relayState = request.getParameter(GeneralConstants.RELAY_STATE);

      if (StringUtil.isNotNull(relayState))
         relayState = RedirectBindingUtil.urlDecode(relayState);

      String samlRequestMessage = request.getParameter(GeneralConstants.SAML_REQUEST_KEY);
      String samlResponseMessage = request.getParameter(GeneralConstants.SAML_RESPONSE_KEY);

      String signature = request.getParameter(GeneralConstants.SAML_SIGNATURE_REQUEST_KEY);
      String sigAlg = request.getParameter(GeneralConstants.SAML_SIG_ALG_REQUEST_KEY);

      boolean containsSAMLRequestMessage = StringUtil.isNotNull(samlRequestMessage);
      boolean containsSAMLResponseMessage = StringUtil.isNotNull(samlResponseMessage);

      Session session = request.getSessionInternal();

      if (containsSAMLRequestMessage || containsSAMLResponseMessage) {
         if (trace)
            log.trace("Storing the SAMLRequest/SAMLResponse and RelayState in session");
         if (StringUtil.isNotNull(samlRequestMessage))
            session.setNote(GeneralConstants.SAML_REQUEST_KEY, samlRequestMessage);
         if (StringUtil.isNotNull(samlResponseMessage))
            session.setNote(GeneralConstants.SAML_RESPONSE_KEY, samlResponseMessage);
         if (StringUtil.isNotNull(relayState))
            session.setNote(GeneralConstants.RELAY_STATE, relayState.trim());
         if (StringUtil.isNotNull(signature))
            session.setNote(GeneralConstants.SAML_SIGNATURE_REQUEST_KEY, signature.trim());
         if (StringUtil.isNotNull(sigAlg))
            session.setNote(GeneralConstants.SAML_SIG_ALG_REQUEST_KEY, sigAlg.trim());

         // Saving request from SP for later use
         saveRequestFromSP(request, session);
      }

      // Lets check if the user has been authenticated
      Principal userPrincipal = request.getPrincipal();


      if (userPrincipal == null)
      {
         if (skipProcessingByNextValves(session))
         {
            userPrincipal = (Principal)session.getNote(Constants.FORM_PRINCIPAL_NOTE);
            request.setUserPrincipal(userPrincipal);
            request.setAuthType(Constants.FORM_METHOD);
            session.setAuthType(Constants.FORM_METHOD);
            if (trace)
            {
               log.trace("Skip processing of request by next valves. Going to SAML processing");
            }
         }
         else
         {
            try {
               // Next in the invocation chain
               getNext().invoke(request, response);
               valveInvocationPerformed = true;
            } finally {
               userPrincipal = request.getPrincipal();
               referer = request.getHeader("Referer");
               if (trace)
                  log.trace("Referer in finally block=" + referer + ":user principal=" + userPrincipal);
            }
         }
      }

      // Restore request from SP if available and if we are in SAML mode (in the middle of SAML login,
      // which means that we are not in standalone application mode)
      if (session.getNote(GeneralConstants.SAML_REQUEST_KEY) != null || session.getNote(GeneralConstants.SAML_RESPONSE_KEY) != null
            || containsSAMLRequestMessage || containsSAMLResponseMessage)
      {
         request = restoreRequestFromSP(request, session);
      }

      IDPWebRequestUtil webRequestUtil = new IDPWebRequestUtil(request, idpConfiguration, keyManager);

      Document samlErrorResponse = null;
      // Look for unauthorized status
      if (response.getStatus() == HttpServletResponse.SC_FORBIDDEN) {
         try {
            samlErrorResponse = webRequestUtil.getErrorResponse(referer, JBossSAMLURIConstants.STATUS_AUTHNFAILED.get(),
                  getIdentityURL(), this.idpConfiguration.isSupportsSignature());

            IDPWebRequestUtil.WebRequestUtilHolder holder = webRequestUtil.getHolder();
            holder.setResponseDoc(samlErrorResponse).setDestination(referer).setRelayState(relayState)
                  .setAreWeSendingRequest(false).setPrivateKey(null).setSupportSignature(false)
                  .setServletResponse(response);
            holder.setPostBindingRequested(webRequestUtil.hasSAMLRequestInPostProfile());

            if (this.idpConfiguration.isSupportsSignature()) {
               holder.setSupportSignature(true).setPrivateKey(keyManager.getSigningKey());
            }

            holder.setStrictPostBinding(this.idpConfiguration.isStrictPostBinding());

            webRequestUtil.send(holder);
         } catch (GeneralSecurityException e) {
            throw new ServletException(e);
         }
         return;
      }

      if (userPrincipal != null) {
         /**
          * Since the container has finished the authentication, we can retrieve the original saml message as well as any
          * relay state from the SP
          */
         samlRequestMessage = (String) session.getNote(GeneralConstants.SAML_REQUEST_KEY);

         samlResponseMessage = (String) session.getNote(GeneralConstants.SAML_RESPONSE_KEY);
         relayState = (String) session.getNote(GeneralConstants.RELAY_STATE);
         signature = (String) session.getNote(GeneralConstants.SAML_SIGNATURE_REQUEST_KEY);
         sigAlg = (String) session.getNote(GeneralConstants.SAML_SIG_ALG_REQUEST_KEY);

         if (trace) {
            StringBuilder builder = new StringBuilder();
            builder.append("Retrieved saml messages and relay state from session");
            builder.append("saml Request message=").append(samlRequestMessage);
            builder.append("::").append("SAMLResponseMessage=");
            builder.append(samlResponseMessage).append(":").append("relay state=").append(relayState);

            builder.append("Signature=").append(signature).append("::sigAlg=").append(sigAlg);
            log.trace(builder.toString());
         }

         // Send valid saml response after processing the request
         if (samlRequestMessage != null) {
            processSAMLRequestMessage(webRequestUtil, request, response);
         } else if (StringUtil.isNotNull(samlResponseMessage)) {
            processSAMLResponseMessage(webRequestUtil, request, response);
         } else {
            String target = request.getParameter(SAML11Constants.TARGET);
            if (StringUtil.isNotNull(target))
            {
               // We have SAML 1.1 IDP first scenario. Now we need to create a SAMLResponse and send back
               // to SP as per target
               handleSAML11(webRequestUtil, request, response);
            }
            else if (skipForwardingToHostedURL)
            {
               if (trace)
                  log.trace("Skip forwarding to Hosted URL and continue with other valves");

               // Next in the invocation chain but only in case, that valve chain haven't been invoked yet
               if (!valveInvocationPerformed)
               {
                  getNext().invoke(request, response);
               }
            }
            else
            {

               if (trace)
                  log.trace("SAML 1.1::Proceeding to IDP index page");
               RequestDispatcher dispatch = context.getServletContext().getRequestDispatcher("/hosted/");
               try {
                  dispatch.forward(request, response);
               } catch (Exception e) {
                  // JBAS5.1 and 6 quirkiness
                  dispatch.forward(request.getRequest(), response);
               }
            }
         }
      }
   }


   @Override
   public void start() throws LifecycleException
   {
      super.start();
      this.context = (Context) getContainer();
      this.keyManager = (TrustKeyManager)getPrivateFieldOfSuperClass("keyManager");

      log.info("Valve started with identityURL=" + getIdentityURL() + ", strictPostBinding=" + idpConfiguration.isStrictPostBinding() + ", keyManager="
            + keyManager + ", context=" + context);
   }


   protected void saveRequestFromSP(Request request, Session session)
   {
      session.setNote(REQUEST_FROM_SP, request);
      session.setNote(REQUEST_FROM_SP_METHOD, request.getMethod());
      if (trace)
      {
         log.trace("Saving request from SP. RequestUrl=" + request.getRequestURI() + ", HTTPMethod=" + request.getMethod());
      }
   }


   protected Request restoreRequestFromSP(Request request, Session session)
   {
      Object tempRequest = session.getNote(REQUEST_FROM_SP);
      if (tempRequest != null)
      {
         request = (Request)tempRequest;
         request.getCoyoteRequest().method().setString((String)session.getNote(REQUEST_FROM_SP_METHOD));
         if (trace)
         {
            log.trace("Restore original request from SP. RequestUrl=" + request.getRequestURI() + ", HTTPMethod=" + request.getMethod());
         }
      }

      return request;
   }


   // We will skip valve processing if we have principal in session and we have SAMLRequest or SAMLResponse in session.
   // This can happen in Tomcat in first request after JAAS authentication.
   // In this case, we won't process request with other valves, but we will go directly to SAML processing
   protected boolean skipProcessingByNextValves(Session session)
   {
      Principal principal = (Principal)session.getNote(Constants.FORM_PRINCIPAL_NOTE);
      String samlRequest = (String)session.getNote(GeneralConstants.SAML_REQUEST_KEY);
      String samlResponse = (String)session.getNote(GeneralConstants.SAML_RESPONSE_KEY);
      return (principal != null && (samlRequest != null || samlResponse != null));
   }


   // Hack to obtain values of private fields from superclass
   private Object getPrivateFieldOfSuperClass(String fieldName)
   {
      try
      {
         Field tempField = AbstractIDPValve.class.getDeclaredField(fieldName);
         tempField.setAccessible(true);
         return tempField.get(this);
      }
      catch (Exception e)
      {
         throw new RuntimeException(e);
      }
   }
}
