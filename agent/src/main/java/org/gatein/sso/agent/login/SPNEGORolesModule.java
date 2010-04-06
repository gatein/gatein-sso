/*
 * JBoss, Home of Professional Open Source.
 * 
 * Copyright 2007, Red Hat Middleware LLC, and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
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

import java.security.Principal;
import java.security.acl.Group;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;

import org.jboss.security.SimpleGroup;
import org.jboss.security.auth.spi.AbstractServerLoginModule;

import org.exoplatform.container.ExoContainer;
import org.exoplatform.container.ExoContainerContext;
import org.exoplatform.container.PortalContainer;
import org.exoplatform.container.RootContainer;
import org.exoplatform.services.security.Identity;
import org.exoplatform.services.security.Authenticator;
import org.exoplatform.services.security.IdentityRegistry;

/**
 * The LoginModule that is responsible for setting up the proper GateIn roles
 * corresponding to the SPNEGO principal that was authenticated
 * 
 * @author <a href="mailto:sshah@redhat.com">Sohil Shah</a>
 */
public class SPNEGORolesModule extends AbstractServerLoginModule
{
	private Identity identity = null;

	// GateIn integration
	private static final String OPTION_PORTAL_CONTAINER_NAME = "portalContainerName";
	private static final String OPTION_REALM_NAME = "realmName";
	private String portalContainerName;
	private String realmName;

	private String getPortalContainerName(Map options)
	{
		if (options != null)
		{
			String optionValue = (String) options.get(OPTION_PORTAL_CONTAINER_NAME);
			if (optionValue != null && optionValue.length() > 0)
			{
				return optionValue;
			}
		}
		return PortalContainer.DEFAULT_PORTAL_CONTAINER_NAME;
	}

	private String getRealmName(Map options)
	{
		if (options != null)
		{
			String optionValue = (String) options.get(OPTION_REALM_NAME);
			if (optionValue != null && optionValue.length() > 0)
			{
				return optionValue;
			}
		}
		return PortalContainer.DEFAULT_REALM_NAME;
	}

	private ExoContainer getContainer() throws Exception
	{
		// TODO set correct current container
		ExoContainer container = ExoContainerContext.getCurrentContainer();
		if (container instanceof RootContainer)
		{
			container = RootContainer.getInstance().getPortalContainer(
					portalContainerName);
		}
		return container;
	}

	@Override
	public void initialize(final Subject subject,
			final CallbackHandler callbackHandler, final Map sharedState,
			final Map options)
	{
		super.initialize(subject, callbackHandler, sharedState, options);

		// GateIn integration
		this.portalContainerName = getPortalContainerName(options);
		this.realmName = getRealmName(options);
	}

	@Override
	public boolean login() throws LoginException
	{
		try
		{
			if (super.login())
			{
				Principal principal = this.getIdentity();
				Authenticator authenticator = (Authenticator) getContainer()
						.getComponentInstanceOfType(Authenticator.class);

				this.identity = authenticator.createIdentity(principal.getName());

				return true;
			}
			else
			{
				return false;
			}
		}
		catch (Exception e)
		{
			throw new LoginException(e.getMessage());
		}
	}

	@Override
	protected Principal getIdentity()
	{
		return (Principal) sharedState.get("javax.security.auth.login.name");
	}

	@Override
	protected Group[] getRoleSets() throws LoginException
	{
		try
		{
			Group roles = new SimpleGroup("Roles");
			for (String role : this.identity.getRoles())
			{
				roles.addMember(this.createIdentity(role));
			}

			Group[] groups = { roles };

			return groups;
		}
		catch (Exception e)
		{
			throw new LoginException(e.getMessage());
		}
	}

	@Override
	public boolean commit() throws LoginException
	{
		try
		{
			if (super.commit())
			{
				IdentityRegistry identityRegistry = (IdentityRegistry) getContainer()
						.getComponentInstanceOfType(IdentityRegistry.class);

				// Check for single check
				if (identityRegistry.getIdentity(this.identity.getUserId()) != null)
				{
					// already logged in
					return true;
				}

				this.identity.setSubject(this.subject);
				identityRegistry.register(this.identity);

				return true;
			}
			else
			{
				return false;
			}
		}
		catch (Exception e)
		{
			throw new LoginException(e.getMessage());
		}
	}
}
