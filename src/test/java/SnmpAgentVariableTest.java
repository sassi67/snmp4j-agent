import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.snmp4j.agent.mo.snmp.RowStatus;
import org.snmp4j.agent.mo.snmp.StorageType;
import org.snmp4j.smi.Integer32;
import org.snmp4j.smi.OctetString;

import static org.junit.jupiter.api.Assertions.*;

public class SnmpAgentVariableTest {
    @Test
    public void testDefaultValues() {
        SnmpAgentVariable v = new SnmpAgentVariable();

        assertEquals(new OctetString("public2public"), v.getVariableName());
        assertEquals(new OctetString("community"), v.getCommunity());
        assertEquals(new OctetString("cpublic"), v.getSecurityName());
        assertNull(v.getLocalEngineID());
        assertEquals(new OctetString("community"), v.getContextName());
        assertEquals(new OctetString(), v.getTransportTag());
        assertEquals(new Integer32(StorageType.nonVolatile), v.getStorageType());
        assertEquals(new Integer32(RowStatus.active), v.getRowStatus());
    }
    @Test
    public void testAssertOnWrongValues() {
        SnmpAgentVariable v = new SnmpAgentVariable();

        final Integer32 wrongRowStatusLow = new Integer32(RowStatus.notExistant - 1);
        Exception exceptionOnWrongRowStatusLow = Assertions.assertThrows(IllegalArgumentException.class, () -> v.setRowStatus(wrongRowStatusLow));
        final String expectedRowStatusMessageLow = "Invalid row status: " + wrongRowStatusLow;
        final String actualRowStatusMessageLow = exceptionOnWrongRowStatusLow.getMessage();
        assertTrue(actualRowStatusMessageLow.contains(expectedRowStatusMessageLow));

        final Integer32 wrongRowStatusHigh = new Integer32(RowStatus.destroy + 1);
        Exception exceptionOnWrongRowStatusHigh = Assertions.assertThrows(IllegalArgumentException.class, () -> v.setRowStatus(wrongRowStatusHigh));
        final String expectedRowStatusMessageHigh = "Invalid row status: " + wrongRowStatusHigh;
        final String actualRowStatusMessageHigh = exceptionOnWrongRowStatusHigh.getMessage();
        assertTrue(actualRowStatusMessageHigh.contains(expectedRowStatusMessageHigh));
    }
}
