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

package org.gatein.sso.josso.plugin;

import org.atricore.idbus.kernel.main.authn.BaseRole;
import org.atricore.idbus.kernel.main.authn.BaseUser;
import org.atricore.idbus.kernel.main.authn.BaseUserImpl;
import org.atricore.idbus.kernel.main.authn.Credential;
import org.atricore.idbus.kernel.main.authn.CredentialKey;
import org.atricore.idbus.kernel.main.authn.CredentialProvider;
import org.atricore.idbus.kernel.main.authn.exceptions.SSOAuthenticationException;
import org.atricore.idbus.kernel.main.authn.scheme.AuthenticationScheme;
import org.atricore.idbus.kernel.main.store.UserKey;
import org.atricore.idbus.kernel.main.store.exceptions.NoSuchUserException;
import org.atricore.idbus.kernel.main.store.exceptions.SSOIdentityException;
import org.atricore.idbus.kernel.main.store.identity.BindContext;
import org.atricore.idbus.kernel.main.store.identity.BindableCredentialStore;
import org.atricore.idbus.kernel.main.store.identity.IdentityStore;

/**
 * Identity plugin implementation for JOSSO 2
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class GateInAtricoreIdentityPlugin extends AbstractIdentityPlugin implements BindableCredentialStore,IdentityStore
{
   private AuthenticationScheme authenticationScheme = null;

   public void setAuthenticationScheme(AuthenticationScheme authenticationScheme)
   {
      this.authenticationScheme = authenticationScheme;
   }

   // ----------------IdentityStore implementation---------------------------------------
   public boolean userExists(UserKey userKey) throws SSOIdentityException
   {
      return true;
   }

   public BaseRole[] findRolesByUserKey(UserKey userKey)
         throws SSOIdentityException
   {
      // Return empty role set for now. We may think about extending auth-callback for obtain GateIn roles via REST.
      return new BaseRole[] {};
   }

   public BaseUser loadUser(UserKey userKey) throws NoSuchUserException,
         SSOIdentityException
   {
      BaseUser user = new BaseUserImpl();
      user.setName(userKey.toString());
      return user;
   }

   // ---------------CredentialStore implementation----------------------------------------------------------
   public Credential[] loadCredentials(CredentialKey credentialKey,
                                       CredentialProvider credentialProvider) throws SSOIdentityException
   {
      return null;
   }

   public Credential[] loadCredentials(CredentialKey credentialKey) throws SSOIdentityException
   {
      return null;
   }

   public String loadUID(CredentialKey key, CredentialProvider cp) throws SSOIdentityException
   {
      return null;
   }

   public boolean bind(String username, String password, BindContext context) throws SSOAuthenticationException
   {
      try
      {
         return bindImpl(username, password);
      }
      catch(Exception e)
      {
         throw new SSOAuthenticationException(e);
      }
   }
}
