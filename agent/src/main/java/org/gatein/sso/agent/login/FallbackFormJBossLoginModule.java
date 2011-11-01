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

package org.gatein.sso.agent.login;

import org.exoplatform.services.security.j2ee.JbossLoginModule;
import org.exoplatform.services.security.jaas.JAASGroup;
import org.exoplatform.services.security.jaas.RolePrincipal;
import org.exoplatform.services.security.jaas.UserPrincipal;

import javax.security.auth.login.LoginException;
import java.security.Principal;
import java.security.acl.Group;
import java.util.Set;

/**
 * This login module is used for SPNEGO integration. It is workaround, which returns only identity of user in method "commit()" and it does not return any groups.
 * It is needed because {@link org.jboss.security.negotiation.spnego.SPNEGOLoginModule} assumes in method usernamePasswordLogin()
 * that user identity is returned as first principal, which is not the case for JbossLoginModule. Issue is addressed in https://issues.jboss.org/browse/SECURITY-631
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class FallbackFormJBossLoginModule extends JbossLoginModule
{
   /**
    * {@inheritDoc}
    */
   @Override
   public boolean commit() throws LoginException
   {
      if (super.commit())
      {
         Set<Principal> principals = subject.getPrincipals();

         // clear existing principals from subject
         principals.clear();

         // add only username principal
         principals.add(new UserPrincipal(identity.getUserId()));

         return true;
      }
      else
      {
         return false;
      }
   }
}
