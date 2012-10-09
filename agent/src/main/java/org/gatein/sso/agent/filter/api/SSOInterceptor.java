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

package org.gatein.sso.agent.filter.api;

import org.exoplatform.container.xml.InitParams;

import javax.servlet.Filter;
import javax.servlet.FilterConfig;

/**
 * SSOInterceptor is actually filter, which can be configured through exo kernel
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public interface SSOInterceptor extends Filter
{
   public void initWithParams(InitParams params);

   /**
    * filter config is needed even if we use kernel (no servlet API) because of calls to getContainer()
    *
    * @param config config passed from SSODelegateFilter
    */
   public void setFilterConfig(FilterConfig config);

}
