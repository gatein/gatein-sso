package org.gatein.sso.agent.tomcat;

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;
import org.gatein.common.logging.Logger;
import org.gatein.common.logging.LoggerFactory;

import javax.servlet.ServletException;
import java.io.IOException;

/**
 * Valve for adding HttpServletRequest and HttpServletResponse into threadLocal so that it can be accessed from
 * Login Modules during authentication.
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class ServletAccessValve extends ValveBase
{
   private static final Logger log = LoggerFactory.getLogger(ServletAccessValve.class);
   
   @Override
   public void invoke(Request request, Response response) throws IOException, ServletException
   {
      ServletAccess.setRequestAndResponse(request, response);
      if (log.isTraceEnabled())
      {
         log.trace("Current HttpServletRequest and HttpServletResponse added to ThreadLocal.");
      }

      try
      {
         getNext().invoke(request, response);
      }
      finally
      {
         ServletAccess.resetRequestAndResponse();
         if (log.isTraceEnabled())
         {
            log.trace("Cleaning ThreadLocal");
         }
      }
   }

}
