package com.compuware.apm.bigtest.extensions.util;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.snmp4j.agent.mo.snmp.StorageType;
import org.snmp4j.agent.mo.snmp.VacmMIB;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class SnmpAgentVacmViewTreeFamilyTest {
    @Test
    public void testDefaultValues() {
        SnmpAgentVacmViewTreeFamily vtf = new SnmpAgentVacmViewTreeFamily();

        assertEquals("Wrong view name", new OctetString("fullReadView"), vtf.getViewName());
        assertEquals("Wrong sub tree name", new OID(), vtf.getSubtree());
        assertEquals("Wrong mask", new OctetString(), vtf.getMask());
        assertEquals("Wrong type", VacmMIB.vacmViewIncluded, vtf.getType());
        assertEquals("Wrong storage type", StorageType.nonVolatile, vtf.getStorageType());
    }
    @Test
    public void testAssertOnWrongValues() {
        SnmpAgentVacmViewTreeFamily vtf = new SnmpAgentVacmViewTreeFamily();

        final int wrongTypeLow = VacmMIB.vacmViewIncluded - 1;
        Exception exceptionOnWrongTypeLow = Assertions.assertThrows(IllegalArgumentException.class, () -> {
            vtf.setType(wrongTypeLow);
        });
        final String expectedTypeMessageLow = "Invalid type view: " + wrongTypeLow;
        final String actualTypeMessageLow = exceptionOnWrongTypeLow.getMessage();
        assertTrue(actualTypeMessageLow.contains(expectedTypeMessageLow));

        final int wrongTypeHigh = VacmMIB.vacmViewExcluded + 1;
        Exception exceptionOnWrongTypeHigh = Assertions.assertThrows(IllegalArgumentException.class, () -> {
            vtf.setType(wrongTypeHigh);
        });
        final String expectedTypeMessageHigh = "Invalid type view: " + wrongTypeHigh;
        final String actualTypeMessageHigh = exceptionOnWrongTypeHigh.getMessage();
        assertTrue(actualTypeMessageHigh.contains(expectedTypeMessageHigh));
    }
}
