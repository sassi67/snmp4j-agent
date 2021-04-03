import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.snmp4j.CommunityTarget;
import org.snmp4j.PDU;
import org.snmp4j.Snmp;
import org.snmp4j.agent.mo.MOAccessImpl;
import org.snmp4j.agent.mo.MOScalar;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.log.Log4jLogFactory;
import org.snmp4j.log.LogFactory;
import org.snmp4j.log.LogLevel;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.smi.*;
import org.snmp4j.transport.DefaultUdpTransportMapping;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;
import static org.snmp4j.agent.BaseAgent.STATE_RUNNING;

public class SnmpAgentV2Test {

	private static final int SYSUPTIME1 = 1235810;
	private static final int SYSUPTIME2 = 1234567;

    private static final String snmpAgentCommunity = "snmptest";
    private static final String snmpAgentAddress = "127.0.0.1";
	private static final OID oidSysUpTime = new OID(".1.3.6.1.2.1.1.3.0");
    private static final Integer32 oidSysUpTimeValue1 =  new Integer32(SYSUPTIME1);
	private static final Integer32 oidSysUpTimeValue2 =  new Integer32(SYSUPTIME2);

    @BeforeAll
    public static void setup() {
        // log everything
        LogFactory.setLogFactory(new Log4jLogFactory());
        org.apache.log4j.BasicConfigurator.configure();
        LogFactory.getLogFactory().getRootLogger().setLogLevel(LogLevel.ALL);
    }

    @Test
    public void testSnmpV2IsHealthy() throws IOException {
        try (SnmpAgent snmpAgent = new SnmpAgentV2(snmpAgentCommunity,
                new MOScalar<>(oidSysUpTime, MOAccessImpl.ACCESS_READ_ONLY, oidSysUpTimeValue1))) {
            ResponseEvent event = getResponseEvent(snmpAgent.getPort());
            assertNotNull(event.getResponse());
            assertEquals(oidSysUpTimeValue1, new Integer32(event.getResponse().get(0).getVariable().toInt()));
        }
    }
	@Test
	public void testSnmpV2MultipleAgents() throws IOException {
    	// different agents can have the same address, but different ports
		try (SnmpAgent snmpAgent1 = new SnmpAgentV2(snmpAgentCommunity, new MOScalar<>(oidSysUpTime, MOAccessImpl.ACCESS_READ_ONLY, oidSysUpTimeValue1));
		SnmpAgent snmpAgent2 = new SnmpAgentV2(snmpAgentCommunity, new MOScalar<>(oidSysUpTime, MOAccessImpl.ACCESS_READ_ONLY, oidSysUpTimeValue2))) {

			ResponseEvent event1 = getResponseEvent(snmpAgent1.getPort());
			assertNotNull(event1.getResponse());
			assertEquals(oidSysUpTimeValue1, new Integer32(event1.getResponse().get(0).getVariable().toInt()));

			ResponseEvent event2 = getResponseEvent(snmpAgent2.getPort());
			assertNotNull(event2.getResponse());
			assertEquals(oidSysUpTimeValue2, new Integer32(event2.getResponse().get(0).getVariable().toInt()));
		}
	}

	@Test
	public void testSnmpV2ChangeCommunityAndRestart() throws IOException {
		try (SnmpAgentV2 snmpAgent = new SnmpAgentV2(snmpAgentCommunity, new MOScalar<>(oidSysUpTime, MOAccessImpl.ACCESS_READ_ONLY, oidSysUpTimeValue1))) {

			final int snmpAgentPort = snmpAgent.getPort();

			// create a snmp client able to query the agent
			Snmp snmpClient = buildSnmpClient();
			PDU pdu = buildPDU(new VariableBinding(oidSysUpTime), PDU.GET);
			CommunityTarget target = buildCommunityTarget(snmpAgentCommunity, snmpAgentPort);
			ResponseEvent event1 = snmpClient.send(pdu, target);
			assertNotNull(event1.getResponse());
			assertEquals(oidSysUpTimeValue1, new Integer32(event1.getResponse().get(0).getVariable().toInt()));

			// change the community string
			final String newSnmpAgentCommunity = "snmptest1";
			snmpAgent.setCommunity(newSnmpAgentCommunity);
			// agent gracefully restarted...
			assertEquals(snmpAgent.getAgentState(), STATE_RUNNING);
			// .. ensure that the port is unchanged
			assertEquals(snmpAgentPort, snmpAgent.getPort());
			// but the client with the old credentials is unable to get a response
			event1 = snmpClient.send(pdu, target);
			assertNull(event1.getResponse());

			// a response is received with the correct target
			CommunityTarget newTarget = buildCommunityTarget(newSnmpAgentCommunity, snmpAgentPort);
			ResponseEvent event2 = snmpClient.send(pdu, newTarget);
			assertNotNull(event2.getResponse());
			assertEquals(oidSysUpTimeValue1, new Integer32(event2.getResponse().get(0).getVariable().toInt()));

		}
	}

	private ResponseEvent getResponseEvent(int agentPort) throws IOException {
		Snmp snmpClient = buildSnmpClient();
		PDU pdu = buildPDU(new VariableBinding(oidSysUpTime), PDU.GET);
		CommunityTarget target = buildCommunityTarget(snmpAgentCommunity, agentPort);

		return snmpClient.send(pdu, target);
	}

	private Snmp buildSnmpClient() throws IOException {
		Snmp snmpClient = new Snmp(new DefaultUdpTransportMapping());
		snmpClient.listen();

		return snmpClient;
	}

	private PDU buildPDU(VariableBinding var, int pduType) throws IOException {
		PDU pdu = new PDU();
		pdu.add(var);
		pdu.setType(pduType);

		return pdu;
	}

	private CommunityTarget buildCommunityTarget(String agentCommunity, int agentPort) {
		CommunityTarget target = new CommunityTarget();
		target.setCommunity(new OctetString(agentCommunity));
		target.setAddress(GenericAddress.parse(String.format("udp:%s/%s", snmpAgentAddress, agentPort)));
		target.setRetries(2);
		target.setTimeout(1500);
		target.setVersion(SnmpConstants.version2c);

		return target;
	}
}
