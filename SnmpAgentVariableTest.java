package com.compuware.apm.bigtest.extensions.util;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.snmp4j.agent.mo.snmp.RowStatus;
import org.snmp4j.agent.mo.snmp.StorageType;
import org.snmp4j.smi.Integer32;
import org.snmp4j.smi.OctetString;

import static org.junit.Assert.*;

public class SnmpAgentVariableTest {
    @Test
    public void testDefaultValues() {
        SnmpAgentVariable v = new SnmpAgentVariable();

        assertEquals("Wrong variable name", new OctetString("public2public"), v.getVariableName());
        assertEquals("Wrong community", new OctetString("community"), v.getCommunity());
        assertEquals("Wrong security name", new OctetString("cpublic"), v.getSecurityName());
        assertNull("Wrong local engine ID name", v.getLocalEngineID());
        assertEquals("Wrong context name", new OctetString("community"), v.getContextName());
        assertEquals("Wrong transport tag", new OctetString(), v.getTransportTag());
        assertEquals("Wrong storage type", new Integer32(StorageType.nonVolatile), v.getStorageType());
        assertEquals("Wrong row status", new Integer32(RowStatus.active), v.getRowStatus());
    }
    @Test
    public void testAssertOnWrongValues() {
        SnmpAgentVariable v = new SnmpAgentVariable();

        final Integer32 wrongRowStatusLow = new Integer32(RowStatus.notExistant - 1);
        Exception exceptionOnWrongRowStatusLow = Assertions.assertThrows(IllegalArgumentException.class, () -> {
            v.setRowStatus(wrongRowStatusLow);
        });
        final String expectedRowStatusMessageLow = "Invalid row status: " + wrongRowStatusLow;
        final String actualRowStatusMessageLow = exceptionOnWrongRowStatusLow.getMessage();
        assertTrue(actualRowStatusMessageLow.contains(expectedRowStatusMessageLow));

        final Integer32 wrongRowStatusHigh = new Integer32(RowStatus.destroy + 1);
        Exception exceptionOnWrongRowStatusHigh = Assertions.assertThrows(IllegalArgumentException.class, () -> {
            v.setRowStatus(wrongRowStatusHigh);
        });
        final String expectedRowStatusMessageHigh = "Invalid row status: " + wrongRowStatusHigh;
        final String actualRowStatusMessageHigh = exceptionOnWrongRowStatusHigh.getMessage();
        assertTrue(actualRowStatusMessageHigh.contains(expectedRowStatusMessageHigh));
    }
}
