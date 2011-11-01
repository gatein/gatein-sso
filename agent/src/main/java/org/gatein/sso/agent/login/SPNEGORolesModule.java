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
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.management.MBeanServer;
import javax.management.ObjectName;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;
import javax.security.jacc.PolicyContext;

import javax.security.jacc.PolicyContextException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.jboss.security.SimpleGroup;
import org.jboss.security.SimplePrincipal;
import org.jboss.security.auth.spi.AbstractServerLoginModule;

import org.exoplatform.container.ExoContainer;
import org.exoplatform.container.ExoContainerContext;
import org.exoplatform.container.PortalContainer;
import org.exoplatform.container.RootContainer;
import org.exoplatform.services.security.Identity;
import org.exoplatform.services.security.Authenticator;
import org.exoplatform.services.security.IdentityRegistry;
import org.exoplatform.container.monitor.jvm.J2EEServerInfo;
import org.exoplatform.services.security.jaas.UserPrincipal;

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
	
	 public boolean logout() throws LoginException
   {
      org.exoplatform.container.monitor.jvm.J2EEServerInfo info = new J2EEServerInfo();
      MBeanServer jbossServer = info.getMBeanServer();

      //
      if (jbossServer != null)
      {
         try
         {

            log.debug("Performing JBoss security manager cache eviction");

            ObjectName securityManagerName = new ObjectName("jboss.security:service=JaasSecurityManager");

           	String userName = null;
            Principal principalToInvalidate = null;
            String sessionId = null;

            // If authentication was performed by Spnego, we have SimplePrincipal
            Set<SimplePrincipal> simplePrincipals = subject.getPrincipals(SimplePrincipal.class);
            if (!simplePrincipals.isEmpty())
            {
               // There should be one non-group principal
               Iterator<SimplePrincipal> iterator = simplePrincipals.iterator();
               while (iterator.hasNext())
               {
                  Principal temp = iterator.next();
                  if (!(temp instanceof SimpleGroup))
                  {
                     principalToInvalidate = temp;
                     userName = principalToInvalidate.getName();

                     //Obtain the httpsession key
                     sessionId = findSessionId();
                     break;
                  }
               }
            }
            // This means that authentication was performned by Form, we have UserPrincipal
            else
            {
               Set<UserPrincipal> userPrincipals = subject.getPrincipals(UserPrincipal.class);
               if (!userPrincipals.isEmpty())
               {
                  // There should be one
                  principalToInvalidate = userPrincipals.iterator().next();
                  userName = principalToInvalidate.getName();
               }
            }

            // Case with recursive call to 'logout' method
            if (principalToInvalidate == null)
            {
               return true;
            }

            log.debug("Going to perform JBoss security manager cache eviction for user " + userName);

            //
            List allPrincipals =
              (List)jbossServer.invoke(securityManagerName, "getAuthenticationCachePrincipals",
                 new Object[]{realmName}, new String[]{String.class.getName()});

            // Make a copy to avoid some concurrent mods
            allPrincipals = new ArrayList(allPrincipals);

            Principal key = findKeyPrincipal(principalToInvalidate, allPrincipals, sessionId);

            // Perform invalidation
            if (key != null)
            {
               jbossServer.invoke(securityManagerName, "flushAuthenticationCache", new Object[]{realmName, key},
                  new String[]{String.class.getName(), Principal.class.getName()});
               log.debug("Performed JBoss security manager cache eviction for user " + userName);
            }
            else
            {
               log.warn("No principal found when performing JBoss security manager cache eviction for user "
                  + userName);
            }
         }
         catch (Exception e)
         {
            log.warn("Could not perform JBoss security manager cache eviction", e);
         }
      }
      else
      {
         log.warn("Could not find mbean server for performing JBoss security manager cache eviction");
      }

      //
      return true;
   }

   private String findSessionId() throws PolicyContextException
   {
      HttpServletRequest request = (HttpServletRequest) PolicyContext.getContext("javax.servlet.http.HttpServletRequest");
      if(request == null)
      {
         return null;
      }

      HttpSession session = request.getSession(false);
      String sessionId = session.getId();
      return sessionId;
   }

   private Principal findKeyPrincipal(Principal subjectPrincipal, List<Principal> allPrincipals, String sessionId)
   {
      Principal key = null;

      // TODO: Investigate possibility to find principal without iteration through allPrincipals
      // Spnego authentication case. Invalidation key starts with sessionId
      if ((subjectPrincipal instanceof SimplePrincipal) && (sessionId != null))
      {
         for (Iterator i = allPrincipals.iterator(); i.hasNext();)
         {
            Principal principal = (Principal)i.next();

            if (principal.getName().startsWith(sessionId))
            {
               key = principal;
               break;
            }
         }
      }
      // Form authentication case
      else
      {
         String userName = subjectPrincipal.getName();
         for (Iterator i = allPrincipals.iterator(); i.hasNext();)
         {
            Principal principal = (Principal)i.next();

            if (principal.getName().equals(userName))
            {
               key = principal;
               break;
            }
         }
      }

      return key;
   }
}
