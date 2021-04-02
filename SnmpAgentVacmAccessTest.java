package com.compuware.apm.bigtest.extensions.util;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.snmp4j.agent.mo.snmp.StorageType;
import org.snmp4j.agent.security.MutableVACM;
import org.snmp4j.security.SecurityLevel;
import org.snmp4j.security.SecurityModel;
import org.snmp4j.smi.OctetString;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class SnmpAgentVacmAccessTest {
    @Test
    public void testDefaultValues() {
        SnmpAgentVacmAccess va = new SnmpAgentVacmAccess();

        assertEquals("Wrong group name", new OctetString("v1v2group"), va.getGroupName());
        assertEquals("Wrong context name", new OctetString("v2context"), va.getContextPrefix());
        assertEquals("Wrong security model", SecurityModel.SECURITY_MODEL_ANY, va.getSecurityModel());
        assertEquals("Wrong security level", SecurityLevel.noAuthNoPriv, va.getSecurityLevel());
        assertEquals("Wrong match", MutableVACM.VACM_MATCH_EXACT, va.getMatch());
        assertEquals("Wrong read view", new OctetString("fullReadView"), va.getReadView());
        assertEquals("Wrong write view", new OctetString("fullWriteView"), va.getWriteView());
        assertEquals("Wrong notify view", new OctetString("fullNotifyView"), va.getNotifyView());
        assertEquals("Wrong storage type", StorageType.nonVolatile, va.getStorageType());
    }

    @Test
    public void testAssertOnWrongValues() {
        SnmpAgentVacmAccess va = new SnmpAgentVacmAccess();

        final int wrongMatchLow = MutableVACM.VACM_MATCH_EXACT - 1;
        Exception exceptionOnWrongMatchLow = Assertions.assertThrows(IllegalArgumentException.class, () -> {
            va.setMatch(wrongMatchLow);
        });
        final String expectedMatchMessageLow = "Invalid match model: " + wrongMatchLow;
        final String actualMatchLow = exceptionOnWrongMatchLow.getMessage();
        assertTrue(actualMatchLow.contains(expectedMatchMessageLow));

        final int wrongMatchHigh = MutableVACM.VACM_MATCH_PREFIX + 1;
        Exception exceptionOnWrongMatchHigh = Assertions.assertThrows(IllegalArgumentException.class, () -> {
            va.setMatch(wrongMatchHigh);
        });
        final String expectedMatchMessageHigh = "Invalid match model: " + wrongMatchHigh;
        final String actualMatchHigh = exceptionOnWrongMatchHigh.getMessage();
        assertTrue(actualMatchHigh.contains(expectedMatchMessageHigh));
        // security model and storage type already covered by SnmpAgentVacmGroupTest
    }
}