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

import java.io.IOException;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.UUID;
import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.servlet.FilterChain;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.gatein.common.logging.Logger;
import org.gatein.common.logging.LoggerFactory;
import org.gatein.common.util.Base64;
import org.gatein.sso.agent.filter.api.AbstractSSOInterceptor;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.Oid;

public class SPNEGOSSOFilter extends AbstractSSOInterceptor {
    private static final Logger log = LoggerFactory.getLogger(AbstractSSOInterceptor.class);

    private static final GSSManager MANAGER = GSSManager.getInstance();

    private LoginContext loginContext;
    private String[] patterns = {"/login", "/spnegosso"};
    private String loginServletPath = "/login";
    private String securityDomain = "spnego-server";

    public SPNEGOSSOFilter() {}

    @Override
    protected void initImpl() {
        String patternParam = this.getInitParameter("patterns");
        if(patternParam != null && !patternParam.isEmpty()) {
            this.patterns = patternParam.split(",");
        }

        String loginServlet = this.getInitParameter("loginServletPath");
        if(loginServlet != null && !loginServlet.isEmpty()) {
            this.loginServletPath = loginServlet;
        }

        String domain = this.getInitParameter("securityDomain");
        if(domain != null && !domain.isEmpty()) {
            this.securityDomain = domain;
        }

        try {
            this.loginContext = new LoginContext(this.securityDomain);
        } catch (LoginException ex) {
            log.warn("Exception while init LoginContext, so SPNEGO SSO will not work", ex);
        }
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        final HttpServletRequest req = (HttpServletRequest)request;
        final HttpServletResponse resp = (HttpServletResponse)response;

        //. Check if this is not spnego login request
        if(!isSpnegoLoginRequest(req)) {
            chain.doFilter(request, response);
            return;
        }

        SPNEGOSSOContext.setCurrentRequest(req);
        final String contextPath = req.getContextPath();
        final String loginURI = contextPath + this.loginServletPath;
        final String requestURI = req.getRequestURI();
        String username = req.getParameter("username");
        final String remoteUser = req.getRemoteUser();

        if(username != null || remoteUser != null) {
            if(!loginURI.equalsIgnoreCase(requestURI)) {
                // Redirect to /login if current request is /spnegosso to avoid error 404
                // when user access to /spnegosso?username=username or when loggedIn user access to /spengosso
                StringBuilder login = new StringBuilder(loginURI);
                if(req.getQueryString() != null) {
                    login.append("?").append(req.getQueryString());
                }
                resp.sendRedirect(login.toString());
            } else {
                chain.doFilter(req, resp);
            }
            return;
        }

        String principal = null;
        final String auth = req.getHeader("Authorization");
        if(auth != null) {
            try {
                principal = this.login(req, resp, auth);
            } catch (Exception ex) {
                log.error("Exception occur when trying to login with SPNEGO", ex);
            }
        }

        if(principal != null && !principal.isEmpty()) {
            username = principal.substring(0, principal.indexOf('@'));
            // We don't need user password when he login using SSO (SPNEGO)
            // But LoginServlet require password is not empty to call login action instead of display input form
            // So, we need to generate a random password
            String password = UUID.randomUUID().toString();

            HttpSession session = req.getSession();
            session.setAttribute("SPNEGO_PRINCIPAL", username);

            StringBuilder login = new StringBuilder(loginURI)
                    .append("?username=")
                    .append(username)
                    .append("&password=")
                    .append(password);
            String initURL = req.getParameter("initialURI");
            if(initURL != null) {
                login.append("&initialURI=").append(initURL);
            }

            resp.sendRedirect(login.toString());
        } else {
            if(!loginURI.equals(requestURI)) {
                RequestDispatcher dispatcher = req.getRequestDispatcher("/login");
                dispatcher.include(req, resp);
            } else {
                chain.doFilter(req, resp);
            }
            resp.setHeader("WWW-Authenticate", "Negotiate");
            resp.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }
    }

    private boolean isSpnegoLoginRequest(HttpServletRequest request) {
        final String uri = request.getRequestURI();
        final String context = request.getContextPath();
        for(String pattern : this.patterns) {
            if(uri.equals(context.concat(pattern))) {
                return true;
            }
        }
        return false;
    }

    private String login(HttpServletRequest req, HttpServletResponse resp, String auth) throws Exception {
        if(this.loginContext == null) {
            return null;
        }
        this.loginContext.login();

        final String principal;
        final String tok = auth.substring("Negotiate".length() + 1);
        final byte[] gss = Base64.decode(tok);

        GSSContext context = null;
        byte[] token = null;
        context = MANAGER.createContext(getServerCredential(loginContext.getSubject()));
        token = context.acceptSecContext(gss, 0, gss.length);

        if (null == token) {
            return null;
        }

        resp.setHeader("WWW-Authenticate", "Negotiate" + ' ' + Base64.encodeBytes(token));

        if (!context.isEstablished()) {
            resp.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return null;
        }

        principal = context.getSrcName().toString();
        context.dispose();

        this.loginContext.logout();

        return principal;
    }


    /**
     * Returns the {@link org.ietf.jgss.GSSCredential} the server uses for pre-authentication.
     *
     * @param subject account server uses for pre-authentication
     * @return credential that allows server to authenticate clients
     * @throws java.security.PrivilegedActionException
     */
    static GSSCredential getServerCredential(final Subject subject)
            throws PrivilegedActionException {

        final PrivilegedExceptionAction<GSSCredential> action =
                new PrivilegedExceptionAction<GSSCredential>() {
                    public GSSCredential run() throws GSSException {
                        return MANAGER.createCredential(
                                null
                                , GSSCredential.INDEFINITE_LIFETIME
                                , getOid()
                                , GSSCredential.ACCEPT_ONLY);
                    }
                };
        return Subject.doAs(subject, action);
    }

    /**
     * Returns the Universal Object Identifier representation of
     * the SPNEGO mechanism.
     *
     * @return Object Identifier of the GSS-API mechanism
     */
    private static Oid getOid() {
        Oid oid = null;
        try {
            oid = new Oid("1.3.6.1.5.5.2");
        } catch (GSSException gsse) {
            gsse.printStackTrace();
        }
        return oid;
    }

    @Override
    public void destroy() {}
}
