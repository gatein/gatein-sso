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

import org.gatein.common.logging.Logger;
import org.gatein.common.logging.LoggerFactory;
import org.gatein.sso.agent.cas.CASAgent;
import org.gatein.sso.agent.josso.JOSSOAgent;
import org.gatein.sso.agent.opensso.OpenSSOAgent;

/**
 * @author soshah
 *
 */
public class InitiateLoginFilter implements Filter
{
    private static Logger log = LoggerFactory.getLogger(InitiateLoginFilter.class);
    private static final int DEFAULT_MAX_NUMBER_OF_LOGIN_ERRORS = 3;

    private String ssoServerUrl;
    private String ssoCookieName;
    private boolean casRenewTicket;
    private String casServiceUrl;
    private String loginUrl;
    private int maxNumberOfLoginErrors;
    
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

       String maxNumberOfLoginErrorsConfig = filterConfig.getInitParameter("maxNumberOfLoginErrors");
       this.maxNumberOfLoginErrors = maxNumberOfLoginErrorsConfig == null ? DEFAULT_MAX_NUMBER_OF_LOGIN_ERRORS : Integer.parseInt(maxNumberOfLoginErrorsConfig);

       log.info("InitiateLoginFilter configuration: ssoServerUrl=" + this.ssoServerUrl +
                ", ssoCookieName=" + this.ssoCookieName +
                ", loginUrl=" + this.loginUrl +
                ", casRenewTicket=" + this.casRenewTicket +
                ", casServiceUrl=" + this.casServiceUrl +
                ", maxNumberOfLoginErrors=" + this.maxNumberOfLoginErrors);
    }

    public void doFilter(ServletRequest request, ServletResponse response,
            FilterChain chain) throws IOException, ServletException 
    {
        try
        {
            HttpServletRequest req = (HttpServletRequest)request;
            HttpServletResponse resp = (HttpServletResponse)response;
            
            this.processSSOToken(req,resp);

            // Redirection can be already performed from processSSOToken call
            if (resp.isCommitted())
            {
               return;
            }

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
                OpenSSOAgent.getInstance(this.ssoServerUrl, this.ssoCookieName).validateTicket(httpRequest, httpResponse);
            }
            catch (IllegalStateException ilse)
            {
               // Somehow cookie failed validation, retry by starting the opensso login process again.
               // To avoid infinite loop of redirects, we are tracking maximum number of SSO errors for this client
               int currentNumberOfErrors = getCountOfUnsuccessfulAttempts(httpRequest);
               log.warn("Count of login errors: " + currentNumberOfErrors);

               if (currentNumberOfErrors >= maxNumberOfLoginErrors)
               {
                  log.warn("Max. number of login errors reached. Rethrowing exception");
                  throw ilse;
               }
               else
               {
                  httpRequest.setAttribute("abort", Boolean.TRUE);
               }
            }
        }
    }

   // Tracking maximum number of SSO errors for this client in session attribute
   private int getCountOfUnsuccessfulAttempts(HttpServletRequest httpRequest)
   {
      Integer currentNumberOfErrors = (Integer)httpRequest.getSession().getAttribute("InitiateLoginFilter.currentNumberOfErrors");
      if (currentNumberOfErrors == null)
      {
         currentNumberOfErrors = 0;
      }

      currentNumberOfErrors = currentNumberOfErrors + 1;
      httpRequest.getSession().setAttribute("InitiateLoginFilter.currentNumberOfErrors", currentNumberOfErrors);

      return currentNumberOfErrors;
   }
}
