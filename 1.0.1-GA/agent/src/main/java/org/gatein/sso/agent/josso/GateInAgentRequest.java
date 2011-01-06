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

package org.gatein.sso.agent.josso;

import org.josso.agent.LocalSession;

import org.josso.agent.http.HttpSSOAgentRequest;
import org.josso.agent.http.JOSSOSecurityContext;

/**
 * 
 * @author <a href="mailto:sgonzalez@josso.org">Sebastian Gonzalez Oyuela</a>
 */
public class GateInAgentRequest extends HttpSSOAgentRequest
{
	private JOSSOSecurityContext ctx;

	public GateInAgentRequest(int action, String sessionId, LocalSession session,
			String assertionId)
	{
		super(action, sessionId, session, assertionId);
	}

	public GateInAgentRequest(int action, String sessionId, LocalSession session)
	{
		super(action, sessionId, session);
	}

	public void setSecurityContext(JOSSOSecurityContext ctx)
	{
		this.ctx = ctx;
	}

	public JOSSOSecurityContext getSecurityContext()
	{
		return this.ctx;
	}

}
