/**
 * 
 */
package org.gatein.sso.agent.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.gatein.common.logging.Logger;
import org.gatein.common.logging.LoggerFactory;
import org.gatein.sso.agent.cas.CASAgent;
import org.gatein.sso.agent.filter.api.AbstractSSOInterceptor;
import org.gatein.sso.agent.josso.JOSSOAgent;
import org.gatein.sso.agent.opensso.OpenSSOAgent;

/**
 * @author soshah
 *
 */
public class InitiateLoginFilter extends AbstractSSOInterceptor
{
    private static Logger log = LoggerFactory.getLogger(InitiateLoginFilter.class);
    private static final int DEFAULT_MAX_NUMBER_OF_LOGIN_ERRORS = 3;

    private String ssoServerUrl;
    private String ssoCookieName;
    private boolean casRenewTicket;
    private String casServiceUrl;
    private String loginUrl;
    private int maxNumberOfLoginErrors;
    private boolean attachUsernamePasswordToLoginURL;

    private CASAgent casAgent;
    private JOSSOAgent jossoAgent;
    private OpenSSOAgent openSSOAgent;

    @Override
    protected void initImpl()
    {
        this.ssoServerUrl = getInitParameter("ssoServerUrl");
        this.ssoCookieName = getInitParameter("ssoCookieName");
        this.loginUrl = getInitParameter("loginUrl");
        
        String casRenewTicketConfig = getInitParameter("casRenewTicket");
        if(casRenewTicketConfig != null)
        {
            this.casRenewTicket = Boolean.parseBoolean(casRenewTicketConfig);
        }
        
        String casServiceUrlConfig = getInitParameter("casServiceUrl");
        if(casServiceUrlConfig != null && casServiceUrlConfig.trim().length()>0)
        {
            casServiceUrl = casServiceUrlConfig;
        }

       String maxNumberOfLoginErrorsConfig = getInitParameter("maxNumberOfLoginErrors");
       this.maxNumberOfLoginErrors = maxNumberOfLoginErrorsConfig == null ? DEFAULT_MAX_NUMBER_OF_LOGIN_ERRORS : Integer.parseInt(maxNumberOfLoginErrorsConfig);

       String attachUsernamePasswordToLoginURLConfig = getInitParameter("attachUsernamePasswordToLoginURL");
       this.attachUsernamePasswordToLoginURL = attachUsernamePasswordToLoginURLConfig == null ? true : Boolean.parseBoolean(attachUsernamePasswordToLoginURLConfig);

       log.info("InitiateLoginFilter configuration: ssoServerUrl=" + this.ssoServerUrl +
                ", ssoCookieName=" + this.ssoCookieName +
                ", loginUrl=" + this.loginUrl +
                ", casRenewTicket=" + this.casRenewTicket +
                ", casServiceUrl=" + this.casServiceUrl +
                ", maxNumberOfLoginErrors=" + this.maxNumberOfLoginErrors +
                ", attachUsernamePasswordToLoginURL=" + this.attachUsernamePasswordToLoginURL
       );
    }

    protected CASAgent getCasAgent()
    {
       if (this.casAgent == null)
       {
          CASAgent casAgent = (CASAgent)getExoContainer().getComponentInstanceOfType(CASAgent.class);
          if (casAgent == null)
          {
             throw new IllegalStateException("CASAgent component not provided in PortalContainer");
          }

          casAgent.setCasServerUrl(this.ssoServerUrl);
          casAgent.setCasServiceUrl(this.casServiceUrl);
          casAgent.setRenewTicket(this.casRenewTicket);
          this.casAgent = casAgent;
       }

       return this.casAgent;
    }

    protected JOSSOAgent getJOSSOAgent()
    {
       if (this.jossoAgent == null)
       {
          JOSSOAgent jossoAgent = (JOSSOAgent)getExoContainer().getComponentInstanceOfType(JOSSOAgent.class);
          if (jossoAgent == null)
          {
             throw new IllegalStateException("JOSSOAgent component not provided in PortalContainer");
          }

          this.jossoAgent = jossoAgent;
       }

       return this.jossoAgent;
    }

    protected OpenSSOAgent getOpenSSOAgent()
    {
       if (this.openSSOAgent == null)
       {
          OpenSSOAgent openssoAgent = (OpenSSOAgent)getExoContainer().getComponentInstanceOfType(OpenSSOAgent.class);
          if (openssoAgent == null)
          {
             throw new IllegalStateException("OpenSSOAgent component not provided in PortalContainer");
          }

          openssoAgent.setServerUrl(ssoServerUrl);
          openssoAgent.setCookieName(ssoCookieName);
          this.openSSOAgent = openssoAgent;
       }

       return this.openSSOAgent;
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

            String loginRedirectURL = resp.encodeRedirectURL(getLoginRedirectUrl(req));
            resp.sendRedirect(loginRedirectURL);

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
            getCasAgent().validateTicket(httpRequest, ticket);
        }
        else if (jossoAssertion != null && jossoAssertion.trim().length() > 0)
        {
           getJOSSOAgent().validateTicket(httpRequest, httpResponse);
        }
        else
        {
            try
            {
               //See if an OpenSSO Token was used
               getOpenSSOAgent().validateTicket(httpRequest, httpResponse);
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

   protected String getLoginRedirectUrl(HttpServletRequest req)
   {
      StringBuilder url = new StringBuilder(this.loginUrl);

      if (attachUsernamePasswordToLoginURL)
      {
         // Use sessionId and system millis as username and password (similar like spnego is doing)
         String fakeUsername = req.getSession().getId() + "_" + String.valueOf(System.currentTimeMillis());
         url.append("?username=").append(fakeUsername).append("&password=").append(fakeUsername);
      }

      return url.toString();
   }
}
