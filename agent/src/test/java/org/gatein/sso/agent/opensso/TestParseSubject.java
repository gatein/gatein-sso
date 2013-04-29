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

package org.gatein.sso.agent.opensso;

import java.util.Properties;

import junit.framework.TestCase;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class TestParseSubject extends TestCase
{

    private String LINUX_STRING = "userdetails.token.id=AQIC5wM2LY4SgtrcwwIrICaSkhcmXs5P-DmDBAc8itxVUt8Lo.*AAJTSQACMDE.*\nuserdetails.attribute.name=uid\nuserdetails.attribute.value=johny\nuserdetails.attribute.name=sn\nuserdetails.attribute.value=johnysn\nuserdetails.attribute.name=userpassword\nuserdetails.attribute.value={SSHA}Ug4jcPDG54L/dZGzvP6AbjjRllvXyDqK0et2Xw==";
    private String WINDOWS_STRING = "userdetails.token.id=AQIC5wM2LY4SfcwwIrICaSkhcmXs5P-DmDBAc8itxVUt8Lo.*AAJTSQACMDE.*\r\nuserdetails.attribute.name=uid\r\nuserdetails.attribute.value=root\r\nuserdetails.attribute.name=sn\r\nuserdetails.attribute.value=rootsn\r\nuserdetails.attribute.name=userpassword\r\nuserdetails.attribute.value={SSHA}Ug4jcPDG54L/dZGzvP6AbjjRllvXyDqK0et2Xw==";
    private String MAC_STRING = "userdetails.token.id=AQIC5wM2LY4SfcwwIrICaSkhcmXs5P-DmDBAc8itxVUt8Lo.*AAJTSQACMDE.*\ruserdetails.attribute.name=uid\ruserdetails.attribute.value=mary\ruserdetails.attribute.name=sn\ruserdetails.attribute.value=marysn\ruserdetails.attribute.name=userpassword\ruserdetails.attribute.value={SSHA}Ug4jcPDG54L/dZGzvP6AbjjRllvXyDqK0et2Xw==";

    public void testParseSubject() throws Exception
    {
        TestOpenSSOAgentImpl agent = new TestOpenSSOAgentImpl();

        // Test linux properties
        Properties linuxProps = agent.loadAttributes(LINUX_STRING);
        assertEquals("johny", linuxProps.get("uid"));
        assertEquals("johnysn", linuxProps.get("sn"));

        // Test windows properties
        Properties windowsProps = agent.loadAttributes(WINDOWS_STRING);
        assertEquals("root", windowsProps.get("uid"));
        assertEquals("rootsn", windowsProps.get("sn"));

        // Test linux properties
        Properties macProps = agent.loadAttributes(MAC_STRING);
        assertEquals("mary", macProps.get("uid"));
        assertEquals("marysn", macProps.get("sn"));
    }

    // Just to access protected method
    private class TestOpenSSOAgentImpl extends OpenSSOAgentImpl
    {

        public TestOpenSSOAgentImpl()
        {
            super(null);
        }

        protected Properties loadAttributes(String response) throws Exception
        {
            return super.loadAttributes(response);
        }

    }
}
