/*
 * Copyright 2015 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.gatein.sso.cas4;

import org.gatein.sso.plugin.RestCallbackCaller;
import org.jasig.cas.authentication.AbstractAuthenticationHandler;
import org.jasig.cas.authentication.BasicCredentialMetaData;
import org.jasig.cas.authentication.Credential;
import org.jasig.cas.authentication.HandlerResult;
import org.jasig.cas.authentication.PreventedException;
import org.jasig.cas.authentication.UsernamePasswordCredential;
import org.jasig.cas.authentication.principal.SimplePrincipal;

import javax.security.auth.login.FailedLoginException;
import java.security.GeneralSecurityException;

/**
 * @author jpkroehling
 */
public class GateInAuthenticationHandler extends AbstractAuthenticationHandler {
    private volatile RestCallbackCaller restCallbackCaller;
    private String gateInProtocol;
    private String gateInHost;
    private String gateInPort;
    private String gateInContext;
    private String httpMethod;

    @Override
    public HandlerResult authenticate(Credential credential) throws GeneralSecurityException, PreventedException {
        UsernamePasswordCredential usernamePasswordCredential = (UsernamePasswordCredential) credential;
        final String username = usernamePasswordCredential.getUsername();
        final String password = usernamePasswordCredential.getPassword();
        try {
            final boolean authenticated = getRestCallbackCaller().executeRemoteCall(username, password);
            if (authenticated) {
                return new HandlerResult(this, new BasicCredentialMetaData(usernamePasswordCredential), new
                        SimplePrincipal(credential.getId()));
            } else {
                throw new FailedLoginException("Failed to login at GateIn with username " + username);
            }
        } catch (Exception e) {
            throw new FailedLoginException("Failed to login at GateIn. Cause: " + e.getMessage());
        }
    }

    @Override
    public boolean supports(Credential credential) {
        return credential instanceof UsernamePasswordCredential;
    }

    private RestCallbackCaller getRestCallbackCaller() {
        if (restCallbackCaller == null) {
            synchronized (this) {
                if (restCallbackCaller == null) {
                    restCallbackCaller = new RestCallbackCaller(gateInProtocol, gateInHost, gateInPort,
                            gateInContext, httpMethod);
                }
            }
        }

        return restCallbackCaller;
    }

    public String getGateInProtocol() {
        return gateInProtocol;
    }

    public void setGateInProtocol(String gateInProtocol) {
        this.gateInProtocol = gateInProtocol;
    }

    public String getGateInHost() {
        return gateInHost;
    }

    public void setGateInHost(String gateInHost) {
        this.gateInHost = gateInHost;
    }

    public String getGateInPort() {
        return gateInPort;
    }

    public void setGateInPort(String gateInPort) {
        this.gateInPort = gateInPort;
    }

    public String getGateInContext() {
        return gateInContext;
    }

    public void setGateInContext(String gateInContext) {
        this.gateInContext = gateInContext;
    }

    public String getHttpMethod() {
        return httpMethod;
    }

    public void setHttpMethod(String httpMethod) {
        this.httpMethod = httpMethod;
    }
}
