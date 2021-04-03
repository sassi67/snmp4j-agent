import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.snmp4j.agent.mo.snmp.StorageType;
import org.snmp4j.agent.security.MutableVACM;
import org.snmp4j.security.SecurityLevel;
import org.snmp4j.security.SecurityModel;
import org.snmp4j.smi.OctetString;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class SnmpAgentVacmAccessTest {
    @Test
    public void testDefaultValues() {
        SnmpAgentVacmAccess va = new SnmpAgentVacmAccess();

        assertEquals(new OctetString("v1v2group"), va.getGroupName());
        assertEquals(new OctetString("v2context"), va.getContextPrefix());
        assertEquals(SecurityModel.SECURITY_MODEL_ANY, va.getSecurityModel());
        assertEquals(SecurityLevel.noAuthNoPriv, va.getSecurityLevel());
        assertEquals(MutableVACM.VACM_MATCH_EXACT, va.getMatch());
        assertEquals(new OctetString("fullReadView"), va.getReadView());
        assertEquals(new OctetString("fullWriteView"), va.getWriteView());
        assertEquals(new OctetString("fullNotifyView"), va.getNotifyView());
        assertEquals(StorageType.nonVolatile, va.getStorageType());
    }

    @Test
    public void testAssertOnWrongValues() {
        SnmpAgentVacmAccess va = new SnmpAgentVacmAccess();

        final int wrongMatchLow = MutableVACM.VACM_MATCH_EXACT - 1;
        Exception exceptionOnWrongMatchLow = Assertions.assertThrows(IllegalArgumentException.class, () -> va.setMatch(wrongMatchLow));
        final String expectedMatchMessageLow = "Invalid match model: " + wrongMatchLow;
        final String actualMatchLow = exceptionOnWrongMatchLow.getMessage();
        assertTrue(actualMatchLow.contains(expectedMatchMessageLow));

        final int wrongMatchHigh = MutableVACM.VACM_MATCH_PREFIX + 1;
        Exception exceptionOnWrongMatchHigh = Assertions.assertThrows(IllegalArgumentException.class, () -> va.setMatch(wrongMatchHigh));
        final String expectedMatchMessageHigh = "Invalid match model: " + wrongMatchHigh;
        final String actualMatchHigh = exceptionOnWrongMatchHigh.getMessage();
        assertTrue(actualMatchHigh.contains(expectedMatchMessageHigh));
        // security model and storage type already covered by SnmpAgentVacmGroupTest
    }
}