package org.gatein.sso.agent.tomcat;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class ServletAccess
{
   
   private static ThreadLocal<Holder> holderThreadLocal = new ThreadLocal<Holder>();

   public static void setRequestAndResponse(HttpServletRequest request, HttpServletResponse response)
   {
      holderThreadLocal.set(new Holder(request, response));
   }
   
   public static void resetRequestAndResponse()
   {
      holderThreadLocal.set(null);
   }
   
   public static HttpServletRequest getRequest()
   {
      Holder holder = holderThreadLocal.get();
      if (holder != null)
      {
         return holder.servletRequest;
      }

      return null;
   }

   public static HttpServletResponse getResponse()
   {
      Holder holder = holderThreadLocal.get();
      if (holder != null)
      {
         return holder.servletResponse;
      }

      return null;
   }
   
   private static class Holder
   {
      private final HttpServletRequest servletRequest;
      private final HttpServletResponse servletResponse;
      
      private Holder(HttpServletRequest servletRequest, HttpServletResponse servletResponse)
      {
         this.servletRequest = servletRequest;
         this.servletResponse = servletResponse;
      }
   }
}
