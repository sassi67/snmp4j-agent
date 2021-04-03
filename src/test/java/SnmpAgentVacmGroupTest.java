import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.snmp4j.agent.mo.snmp.StorageType;
import org.snmp4j.security.SecurityModel;
import org.snmp4j.smi.OctetString;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class SnmpAgentVacmGroupTest {
    @Test
    public void testDefaultValues() {
        SnmpAgentVacmGroup vg = new SnmpAgentVacmGroup();

        assertEquals(SecurityModel.SECURITY_MODEL_SNMPv2c, vg.getSecurityModel());
        assertEquals(new OctetString("cpublic"), vg.getSecurityName());
        assertEquals(new OctetString("v1v2group"), vg.getGroupName());
        assertEquals(StorageType.nonVolatile, vg.getStorageType());
    }

    @Test
    public void testAssertOnWrongValues() {
        SnmpAgentVacmGroup vg = new SnmpAgentVacmGroup();

        final int wrongSecurityModelLow = SecurityModel.SECURITY_MODEL_ANY - 1;
        Exception exceptionOnWrongSecurityModelLow = Assertions.assertThrows(IllegalArgumentException.class, () -> vg.setSecurityModel(wrongSecurityModelLow));
        final String expectedSecurityModelMessageLow = "Invalid security model: " + wrongSecurityModelLow;
        final String actualSecurityModelMessageLow = exceptionOnWrongSecurityModelLow.getMessage();
        assertTrue(actualSecurityModelMessageLow.contains(expectedSecurityModelMessageLow));

        final int wrongSecurityModelHigh = SecurityModel.SECURITY_MODEL_TSM + 1;
        Exception exceptionOnWrongSecurityModelHigh = Assertions.assertThrows(IllegalArgumentException.class, () -> vg.setSecurityModel(wrongSecurityModelHigh));
        final String expectedSecurityModelMessageHigh = "Invalid security model: " + wrongSecurityModelHigh;
        final String actualSecurityModelMessageHigh = exceptionOnWrongSecurityModelHigh.getMessage();
        assertTrue(actualSecurityModelMessageHigh.contains(expectedSecurityModelMessageHigh));

        final int wrongStorageTypeLow = StorageType.other - 1;
        Exception exceptionOnWrongStorageTypeLow = Assertions.assertThrows(IllegalArgumentException.class, () -> vg.setStorageType(wrongStorageTypeLow));
        final String expectedStorageTypeMessageLow = "Invalid storage type: " + wrongStorageTypeLow;
        final String actualStorageTypeMessageLow = exceptionOnWrongStorageTypeLow.getMessage();
        assertTrue(actualStorageTypeMessageLow.contains(expectedStorageTypeMessageLow));

        final int wrongStorageTypeHigh = StorageType.readOnly + 1;
        Exception exceptionOnWrongStorageType = Assertions.assertThrows(IllegalArgumentException.class, () -> vg.setStorageType(wrongStorageTypeHigh));
        final String expectedStorageTypeMessageHigh = "Invalid storage type: " + wrongStorageTypeHigh;
        final String actualStorageTypeMessageHigh = exceptionOnWrongStorageType.getMessage();
        assertTrue(actualStorageTypeMessageHigh.contains(expectedStorageTypeMessageHigh));
    }
}
