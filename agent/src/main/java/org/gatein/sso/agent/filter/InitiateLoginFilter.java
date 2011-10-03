/**
 * 
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
import javax.servlet.http.HttpServletResponse;

import org.gatein.sso.agent.cas.CASAgent;
import org.gatein.sso.agent.josso.JOSSOAgent;
import org.gatein.sso.agent.opensso.OpenSSOAgent;

/**
 * @author soshah
 *
 */
public class InitiateLoginFilter implements Filter 
{
    private String ssoServerUrl;
    private String ssoCookieName;
    private boolean casRenewTicket;
    private String casServiceUrl;
    private String loginUrl;
    
    public void init(FilterConfig filterConfig) throws ServletException 
    {
        this.ssoServerUrl = filterConfig.getInitParameter("ssoServerUrl");
        this.ssoCookieName = filterConfig.getInitParameter("ssoCookieName");
        this.loginUrl = filterConfig.getInitParameter("loginUrl");
        
        String casRenewTicketConfig = filterConfig.getInitParameter("casRenewTicket");
        if(casRenewTicketConfig != null)
        {
            this.casRenewTicket = Boolean.parseBoolean(casRenewTicketConfig);
        }
        
        String casServiceUrlConfig = filterConfig.getInitParameter("casServiceUrl");
        if(casServiceUrlConfig != null && casServiceUrlConfig.trim().length()>0)
        {
            casServiceUrl = casServiceUrlConfig;
        }
    }

    public void doFilter(ServletRequest request, ServletResponse response,
            FilterChain chain) throws IOException, ServletException 
    {
        try
        {
            HttpServletRequest req = (HttpServletRequest)request;
            HttpServletResponse resp = (HttpServletResponse)response;
            
            this.processSSOToken(req,resp); 
            
            String portalContext = req.getContextPath();
            if(req.getAttribute("abort") != null)
            {
                String ssoRedirect = portalContext + "/sso";
                resp.sendRedirect(ssoRedirect);
                return;
            }
            
            resp.sendRedirect(loginUrl);
			return;
        }
        catch(Exception e)
        {
            throw new ServletException(e);
        }
    }

    public void destroy() 
    {    
    }
    
    private void processSSOToken(HttpServletRequest httpRequest, HttpServletResponse httpResponse) throws Exception
    {
        String ticket = httpRequest.getParameter("ticket");
        String jossoAssertion = httpRequest.getParameter("josso_assertion_id");

        if (ticket != null && ticket.trim().length() > 0)
        {
            CASAgent casagent = CASAgent.getInstance(this.ssoServerUrl, this.casServiceUrl);
            casagent.setRenewTicket(this.casRenewTicket);
            casagent.validateTicket(httpRequest, ticket);
        }
        else if (jossoAssertion != null && jossoAssertion.trim().length() > 0)
        {
            //the JOSSO Agent. This will need to the new client side JOSSO stack that can run on 5.1.0.GA
            JOSSOAgent.getInstance().validateTicket(httpRequest,httpResponse);
        }
        else
        {
            try
            {
                //See if an OpenSSO Token was used
                OpenSSOAgent.getInstance(this.ssoServerUrl, this.ssoCookieName).validateTicket(httpRequest);
            }
            catch(IllegalStateException ilse)
            {
                //somehow cookie failed validation, retry by starting the opensso login process again
                httpRequest.setAttribute("abort", Boolean.TRUE);
            }
        }
    }       
}
