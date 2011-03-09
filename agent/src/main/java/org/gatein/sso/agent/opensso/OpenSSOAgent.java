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
package org.gatein.sso.agent.opensso;

import java.io.InputStream;
import java.util.Properties;

import org.apache.log4j.Logger;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.Cookie;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.PostMethod;

import org.gatein.wci.security.Credentials;

/**
 * @author <a href="mailto:sshah@redhat.com">Sohil Shah</a>
 */
public class OpenSSOAgent
{
	private static Logger log = Logger.getLogger(OpenSSOAgent.class);
	private static OpenSSOAgent singleton;
	
	private String cookieName;
	private String serverUrl;
	
	private OpenSSOAgent(String serverUrl, String cookieName)
	{		
		this.serverUrl = serverUrl;
		this.cookieName = cookieName;		
	}
	
	public static OpenSSOAgent getInstance(String serverUrl, String cookieName)
	{
		if(OpenSSOAgent.singleton == null)
		{
			synchronized(OpenSSOAgent.class)
			{
				if(OpenSSOAgent.singleton == null)
				{										
					OpenSSOAgent.singleton = new OpenSSOAgent(serverUrl, cookieName);
				}
			}
		}
		return OpenSSOAgent.singleton;
	}
		
	public void validateTicket(HttpServletRequest httpRequest) throws Exception
	{						
		String token = null;
		Cookie[] cookies = httpRequest.getCookies();
		if(cookies == null)
		{
		    return;
		}
		
		for(Cookie cookie: cookies)
		{
			if(cookie.getName().equals(this.cookieName))
			{
				token = cookie.getValue();
				break;
			}
		}
		
		if(token == null)
		{
		    throw new IllegalStateException("No SSO Tokens Found");
		}
						
		if(token != null)
		{
			boolean isValid = this.isTokenValid(token);
			
			if(!isValid)
			{
				throw new IllegalStateException("OpenSSO Token is not valid!!");
			}
		
			String subject = this.getSubject(token);			
			if(subject != null)
			{
				Credentials credentials = new Credentials(subject, "");
				httpRequest.getSession().setAttribute(Credentials.CREDENTIALS, credentials);
				httpRequest.getSession().setAttribute("username", subject);
			}
		}
	}	
	//-------------------------------------------------------------------------------------------------------------------------------------------------------------------
	private boolean isTokenValid(String token) throws Exception
	{
		HttpClient client = new HttpClient();
		PostMethod post = null;
		try
		{			
			String url = this.serverUrl+"/identity/isTokenValid";
			post = new PostMethod(url);
			post.addParameter("tokenid", token);
			
			int status = client.executeMethod(post);
			String response = post.getResponseBodyAsString();
			
			log.debug("-------------------------------------------------------");
			log.debug("Status: "+status);
			log.debug("Response: "+response);
			log.debug("-------------------------------------------------------");
			
			if(response.contains(Boolean.TRUE.toString()))
			{
				return true;
			}
			
			return false;
		}
		finally
		{
			if(post != null)
			{
				post.releaseConnection();
			}
		}
	}	
	
	private String getSubject(String token) throws Exception
	{
		HttpClient client = new HttpClient();
		PostMethod post = null;
		try
		{	
			String uid = null;
			String url = this.serverUrl+"/identity/attributes";
			post = new PostMethod(url);
			post.addParameter("subjectid", token);
			post.addParameter("attributes_names", "uid");
			
			int status = client.executeMethod(post);
			String response = post.getResponseBodyAsString();
			
			log.debug("--------------------------------------------------------");
			log.debug("Status: "+status);
			log.debug(response);
			log.debug("--------------------------------------------------------");
			
			if(response != null)
			{
				Properties properties = this.loadAttributes(response);												
				uid = properties.getProperty("uid");
			}
			
			
			return uid;
		}
		finally
		{
			if(post != null)
			{
				post.releaseConnection();
			}
		}		
	}
	
	private Properties loadAttributes(String response) throws Exception
	{
		InputStream is = null;
		try
		{
			Properties properties = new Properties();		
			
			String[] tokens = response.split("\n");
			String name = null;
			for(String token: tokens)
			{
				if(token.startsWith("userdetails.attribute.name"))
				{
					name = token.substring(token.indexOf("=")+1);
				}
				else if(token.startsWith("userdetails.attribute.value"))
				{
					String value = token.substring(token.indexOf("=")+1);
					
					if(name != null)
					{						
						properties.setProperty(name, value);
					}
					
					//cleanup
					name = null;
				}
			}
			
			return properties;
		}
		finally
		{
			if(is != null)
			{
				is.close();
			}
		}
	}
}
