/*
 * Copyright (C) 2012 eXo Platform SAS.
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
package org.gatein.security.sso.spnego;

import javax.security.auth.login.LoginException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import org.exoplatform.container.ExoContainer;
import org.exoplatform.services.log.ExoLogger;
import org.exoplatform.services.log.Log;
import org.exoplatform.services.security.Authenticator;
import org.exoplatform.services.security.Identity;
import org.exoplatform.services.security.UsernameCredential;
import org.exoplatform.services.security.jaas.AbstractLoginModule;

public class SPNEGOSSOLoginModule extends AbstractLoginModule {
    private static final Log log = ExoLogger.getLogger(SPNEGOSSOLoginModule.class);

    public static final String OPTION_ENABLE_FALLBACK_FORM_AUTHENTICATION = "enableFormAuthentication";

    @Override
    protected Log getLogger() {
        return log;
    }

    @Override
    public boolean login() throws LoginException {
        try {
            ExoContainer container = getContainer();

            HttpServletRequest servletRequest = SPNEGOSSOContext.getCurrentRequest();
            if (servletRequest == null) {
                log.debug("HttpServletRequest is null. SPNEGOLoginModule will be ignored.");
                return false;
            }

            HttpSession session = servletRequest.getSession();
            String username = (String)session.getAttribute("SPNEGO_PRINCIPAL");
            if(username != null) {
                establishSecurityContext(container, username);
                if (log.isTraceEnabled()) {
                    log.trace("Successfully established security context for user " + username);
                }
                return true;
            }

        } catch (Exception ex) {
            log.error("Exception when trying to login with SPNEGO", ex);
        }

        // Disable fallback to FORM authentication
        if("false".equalsIgnoreCase((String)this.options.get(OPTION_ENABLE_FALLBACK_FORM_AUTHENTICATION))) {
            throw new LoginException("FORM authentication was disabled by SPNEGO login module.");
        }

        return false;
    }

    @Override
    public boolean commit() throws LoginException {
        return true;
    }

    @Override
    public boolean abort() throws LoginException {
        return true;
    }

    @Override
    public boolean logout() throws LoginException {
        return true;
    }

    protected void establishSecurityContext(ExoContainer container, String username) throws Exception {
        Authenticator authenticator = container.getComponentInstanceOfType(Authenticator.class);

        if (authenticator == null) {
            throw new LoginException("No Authenticator component found, check your configuration");
        }

        Identity identity = authenticator.createIdentity(username);

        sharedState.put("exo.security.identity", identity);
        sharedState.put("javax.security.auth.login.name", username);
        subject.getPublicCredentials().add(new UsernameCredential(username));
    }
}
