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

package org.gatein.sso.agent.saml;

import org.gatein.common.logging.Logger;
import org.gatein.common.logging.LoggerFactory;
import org.gatein.wci.ServletContainerFactory;
import org.picketlink.identity.federation.core.exceptions.ProcessingException;
import org.picketlink.identity.federation.core.saml.v2.interfaces.SAML2HandlerRequest;
import org.picketlink.identity.federation.core.saml.v2.interfaces.SAML2HandlerResponse;
import org.picketlink.identity.federation.saml.v2.protocol.LogoutRequestType;
import org.picketlink.identity.federation.saml.v2.protocol.ResponseType;
import org.picketlink.identity.federation.saml.v2.protocol.StatusResponseType;
import org.picketlink.identity.federation.web.core.HTTPContext;
import org.picketlink.identity.federation.web.handlers.saml2.SAML2LogOutHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Extension of {@link SAML2LogOutHandler} because we need to enforce WCI (crossContext) logout in portal environment.
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class PortalSAML2LogOutHandler extends SAML2LogOutHandler
{
   private static Logger log = LoggerFactory.getLogger(PortalSAML2LogOutHandler.class);
   
   @Override
   public void handleRequestType(SAML2HandlerRequest request, SAML2HandlerResponse response) throws ProcessingException
   {
      if (request.getSAML2Object() instanceof LogoutRequestType == false)
      {
         return;
      }
      
      HTTPContext httpContext = (HTTPContext) request.getContext();
      HttpServletRequest servletRequest = httpContext.getRequest();
      HttpServletResponse servletResponse = httpContext.getResponse();
      
      // Handle SAML logout request by superclass
      super.handleRequestType(request, response);

      // Check if session has been invalidated by superclass. If yes,we need to perform "full" logout at portal level by call WCI logout.
      if (servletRequest.getSession(false) == null)
      {
         portalLogout(servletRequest, servletResponse);
      }
   }

   @Override
   public void handleStatusResponseType(SAML2HandlerRequest request, SAML2HandlerResponse response)
         throws ProcessingException
   {
      //We do not handle any ResponseType (authentication etc)
      if (request.getSAML2Object() instanceof ResponseType)
         return;

      if (request.getSAML2Object() instanceof StatusResponseType == false)
         return;


      HTTPContext httpContext = (HTTPContext) request.getContext();
      HttpServletRequest servletRequest = httpContext.getRequest();
      HttpServletResponse servletResponse = httpContext.getResponse();

      // Handle SAML logout response by superclass
      super.handleStatusResponseType(request, response);

      // Check if session has been invalidated by superclass. If yes,we need to perform "full" logout at portal level by call WCI logout.
      if (servletRequest.getSession(false) == null)
      {
         portalLogout(servletRequest, servletResponse);
      }

   }

   /**
    * Performs portal logout by calling WCI logout.
    * 
    * @param request
    * @param response
    */
   protected void portalLogout(HttpServletRequest request, HttpServletResponse response)
   {
      // Workaround: we need to temporary "restore" session to enforce crossContext logout at WCI layer
      request.getSession(true);

      try
      {
         ServletContainerFactory.getServletContainer().logout(request, response);
      }
      catch (Exception e)
      {
         String message = "Session has been invalidated but WCI logout failed.";
         log.warn(message);
         if (log.isTraceEnabled())
         {
            log.trace(message, e);
         }
      }
   }
   
}
