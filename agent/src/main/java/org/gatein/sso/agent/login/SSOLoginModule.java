/*
 * JBoss, a division of Red Hat
 * Copyright 2006, Red Hat Middleware, LLC, and individual contributors as indicated
 * by the @authors tag. See the copyright.txt in the distribution for a
 * full listing of individual contributors.
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
package org.gatein.sso.agent.login;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.login.LoginException;

import org.exoplatform.container.ExoContainer;
import org.exoplatform.services.log.ExoLogger;
import org.exoplatform.services.log.Log;
import org.exoplatform.services.security.Authenticator;
import org.exoplatform.services.security.Identity;
import org.exoplatform.services.security.UsernameCredential;
import org.exoplatform.services.security.jaas.AbstractLoginModule;
import org.exoplatform.web.security.Credentials;
import org.exoplatform.web.security.security.CookieTokenService;
import org.exoplatform.web.security.security.TransientTokenService;

/**
 * @author <a href="mailto:sshah@redhat.com">Sohil Shah</a>
 */
public final class SSOLoginModule extends AbstractLoginModule
{
	private static final Log LOG = ExoLogger.getLogger(SSOLoginModule.class
			.getName());

	protected Log getLogger()
	{
		return LOG;
	}

	public boolean login() throws LoginException
	{
		try
		{
			Callback[] callbacks = new Callback[2];
			callbacks[0] = new NameCallback("Username");
			callbacks[1] = new PasswordCallback("Password", false);
			callbackHandler.handle(callbacks);

			String password = new String(((PasswordCallback) callbacks[1])
					.getPassword());

			ExoContainer container = getContainer();
			Object o = ((TransientTokenService) container
					.getComponentInstanceOfType(TransientTokenService.class))
					.validateToken(password, true);
			if (o == null)
				o = ((CookieTokenService) container
						.getComponentInstanceOfType(CookieTokenService.class))
						.validateToken(password, false);
			
			String username = null;
			if (o instanceof Credentials)
			{
				Credentials wc = (Credentials)o;
				username = wc.getUsername();
			}

			if (username == null)
			{
					//SSO token could not be validated...hence a user id cannot be found
				  LOG.error("---------------------------------------------------------");
				  LOG.error("SSOLogin Failed. Credential Not Found!!");
				  LOG.error("---------------------------------------------------------");
					return false;
			}
				

			Authenticator authenticator = (Authenticator) getContainer()
					.getComponentInstanceOfType(Authenticator.class);

			if (authenticator == null)
			{
					throw new LoginException(
						"No Authenticator component found, check your configuration");
			}

			Identity identity = authenticator.createIdentity(username);

			sharedState.put("exo.security.identity", identity);
			sharedState.put("javax.security.auth.login.name", username);
			subject.getPublicCredentials().add(new UsernameCredential(username));

			return true;
		}
		catch (final Throwable e)
		{
			throw new LoginException(e.getMessage());
		}
	}

	public boolean logout() throws LoginException
	{
		return true;
	}

	public boolean abort() throws LoginException
	{
		return true;
	}

	public boolean commit() throws LoginException
	{
		return true;
	}
}
