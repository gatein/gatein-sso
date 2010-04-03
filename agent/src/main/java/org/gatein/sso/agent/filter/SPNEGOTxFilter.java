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
package org.gatein.sso.agent.filter;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import javax.transaction.TransactionManager;
import javax.transaction.Status;
import javax.naming.InitialContext;

import org.exoplatform.container.web.AbstractFilter;
import org.exoplatform.services.organization.OrganizationService;
import org.exoplatform.services.organization.User;

/**
 * @author <a href="mailto:sshah@redhat.com">Sohil Shah</a>
 */
public class SPNEGOTxFilter extends AbstractFilter
{
	
	public void destroy()
	{
	}

	public void doFilter(ServletRequest request, ServletResponse response,
			FilterChain chain) throws IOException, ServletException
	{
		HttpServletRequest httpRequest = (HttpServletRequest)request;
		
		boolean isStartedHere = this.startTx();		
		try
		{
			String remoteUser = httpRequest.getRemoteUser();
			
			System.out.println("-----------------------------------------------------------------");
			System.out.println("SPNEGO TX Filter invoked...(TX Started: )"+isStartedHere);
			System.out.println("RequestURL: "+httpRequest.getRequestURI());
			System.out.println("RemoteUser: "+remoteUser);			
			
			if(remoteUser != null)
			{
				OrganizationService orgService =
                  (OrganizationService)getContainer().getComponentInstanceOfType(OrganizationService.class);
				User user = orgService.getUserHandler().findUserByName(remoteUser);
				
				System.out.println("Exo User: "+user);
			}
			System.out.println("-----------------------------------------------------------------");
			
			chain.doFilter(request, response);
			
			if(isStartedHere)
			{				
				this.commit();
			}
		}
		catch(Throwable t)
		{
			t.printStackTrace();
			
			if(isStartedHere)
			{
				this.rollback();
			}
			
			throw new RuntimeException(t);
		}
	}
	
	private boolean startTx()
	{
		try
		{
			TransactionManager tm = (TransactionManager)new InitialContext().lookup("java:/TransactionManager");
			
			if(tm.getStatus() == Status.STATUS_NO_TRANSACTION)
			{
				tm.begin();
				return true;
			}
			
			return false;
		}
		catch(Throwable t)
		{
			t.printStackTrace();
			return false;
		}
	}
	
	private void commit()
	{
		try
		{
			TransactionManager tm = (TransactionManager)new InitialContext().lookup("java:/TransactionManager");
			tm.commit();
		}
		catch(Throwable t)
		{
			t.printStackTrace();
			throw new RuntimeException(t);
		}
	}
	
	private void rollback()
	{
		try
		{
			TransactionManager tm = (TransactionManager)new InitialContext().lookup("java:/TransactionManager");
			tm.rollback();
		}
		catch(Throwable t)
		{
			t.printStackTrace();
			throw new RuntimeException(t);
		}
	}
}
