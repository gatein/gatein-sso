<%--

    Copyright (C) 2009 eXo Platform SAS.
    
    This is free software; you can redistribute it and/or modify it
    under the terms of the GNU Lesser General Public License as
    published by the Free Software Foundation; either version 2.1 of
    the License, or (at your option) any later version.
    
    This software is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
    Lesser General Public License for more details.
    
    You should have received a copy of the GNU Lesser General Public
    License along with this software; if not, write to the Free
    Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
    02110-1301 USA, or see the FSF site: http://www.fsf.org.

--%>

<%@ page import="java.net.URLEncoder"%>
<%@ page import="javax.servlet.http.Cookie"%>
<%@ page import="org.exoplatform.container.PortalContainer"%>
<%@ page import="org.exoplatform.services.resources.ResourceBundleService"%>
<%@ page import="java.util.ResourceBundle"%>
<%@ page import="org.exoplatform.web.login.InitiateLoginServlet"%>
<%@ page language="java" %>
<%@ page contentType="text/html; charset=utf-8" %>

<html>
	<head>
		<script type="text/javascript">		    
			window.location = 'http://localhost:8888/josso/signon/login.do?josso_back_to=http://localhost:8080/portal/private/classic';
		</script>
	</head>
	<body>
	</body>
</html>