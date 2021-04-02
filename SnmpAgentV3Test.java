package com.compuware.apm.bigtest.extensions.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.snmp4j.agent.BaseAgent.STATE_RUNNING;

import java.io.IOException;

import org.junit.Ignore;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.snmp4j.CommandResponder;
import org.snmp4j.CommandResponderEvent;
import org.snmp4j.MessageException;
import org.snmp4j.PDU;
import org.snmp4j.ScopedPDU;
import org.snmp4j.Snmp;
import org.snmp4j.UserTarget;
import org.snmp4j.agent.mo.MOAccessImpl;
import org.snmp4j.agent.mo.MOScalar;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.log.Log4jLogFactory;
import org.snmp4j.log.LogFactory;
import org.snmp4j.log.LogLevel;
import org.snmp4j.mp.MPv3;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.security.SecurityLevel;
import org.snmp4j.security.SecurityModels;
import org.snmp4j.security.SecurityProtocols;
import org.snmp4j.security.USM;
import org.snmp4j.security.UsmUser;
import org.snmp4j.smi.GenericAddress;
import org.snmp4j.smi.Integer32;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.VariableBinding;
import org.snmp4j.transport.DefaultUdpTransportMapping;

public class SnmpAgentV3Test {
    private static final int SYSUPTIME = 1235810;

    private static final String snmpAgentAddress = "127.0.0.1";
	private static final OID oidSysUpTime = new OID(".1.3.6.1.2.1.1.3.0");
    private static final Integer32 oidSysUpTimeValue =  new Integer32(SYSUPTIME);
	private static final SnmpAgentV3.Credentials v3Credentials = new SnmpAgentV3.Credentials("snmptest_SHA_AES256", SecurityLevel.authPriv,
		"SHA", "12345678", "AES256", "12345678");

	@BeforeAll
    public static void setup() {
        // log everything
        LogFactory.setLogFactory(new Log4jLogFactory());
        org.apache.log4j.BasicConfigurator.configure();
        LogFactory.getLogFactory().getRootLogger().setLogLevel(LogLevel.ALL);
    }

    @Test
    public void testSnmpV3IsHealthy() throws IOException {

        try (SnmpAgentV3 snmpAgent = new SnmpAgentV3(v3Credentials,
                new MOScalar<>(oidSysUpTime, MOAccessImpl.ACCESS_READ_ONLY, oidSysUpTimeValue))) {
            ResponseEvent event = getResponseEvent(v3Credentials, snmpAgent.getPort(), snmpAgent.getContextName());
            assertNotNull(event.getResponse());
            assertEquals(oidSysUpTimeValue, new Integer32(event.getResponse().get(0).getVariable().toInt()));
        }
    }

	@Test
	@Disabled
	public void testSnmpV3ChangeUserNameAndRestart() throws IOException {

		try (SnmpAgentV3 snmpAgent = new SnmpAgentV3(v3Credentials,
				new MOScalar<>(oidSysUpTime, MOAccessImpl.ACCESS_READ_ONLY, oidSysUpTimeValue))) {

			final int snmpAgentPort = snmpAgent.getPort();
			Snmp snmpClient = buildSnmpClient(v3Credentials, snmpAgentPort);
			PDU pdu = buildPDU(new VariableBinding(oidSysUpTime), PDU.GET, snmpAgent.getContextName());
			UserTarget target = buildUserTarget(v3Credentials, snmpAgentPort);

			ResponseEvent event1 = snmpClient.send(pdu, target);
			assertNotNull(event1.getResponse());
			assertEquals(oidSysUpTimeValue, new Integer32(event1.getResponse().get(0).getVariable().toInt()));
			// change the username
			final String newSnmpUserName = "snmptest_SHA_AES256_1";
			snmpAgent.setUserName(newSnmpUserName);
			// agent gracefully restarted...
			assertEquals(snmpAgent.getAgentState(), STATE_RUNNING);
			// .. ensure that the port is unchanged
			assertEquals(snmpAgentPort, snmpAgent.getPort());
			// but the client with the old credentials is unable to get a response
			Exception exceptionOnWrongUserName = Assertions.assertThrows(MessageException.class, () -> {
				snmpClient.send(pdu, target);
			});

		}
	}

    private ResponseEvent getResponseEvent(SnmpAgentV3.Credentials v3Credentials, int agentPort, OctetString contextName) throws IOException {
        Snmp snmpClient = buildSnmpClient(v3Credentials, agentPort);
        PDU pdu = buildPDU(new VariableBinding(oidSysUpTime), PDU.GET, contextName);
        UserTarget target = buildUserTarget(v3Credentials, agentPort);

        return snmpClient.send(pdu, target);
    }

    private Snmp buildSnmpClient(SnmpAgentV3.Credentials v3Credentials, int port) throws IOException {
		Snmp snmpClient = new Snmp();
		snmpClient.getMessageDispatcher().addCommandResponder(new CommandResponder() {

			@Override
			public void processPdu(CommandResponderEvent event) {
				System.out.println(event.toString());
			}
		});
		// Very important to add snmp as command responder which will finally process the PDU:
		snmpClient.getMessageDispatcher().addCommandResponder(snmpClient);

		snmpClient.addTransportMapping(new DefaultUdpTransportMapping());
		snmpClient.getMessageDispatcher().addMessageProcessingModel(new MPv3());
		SecurityProtocols.getInstance().addDefaultProtocols();

		final OctetString localEngineId = new OctetString(MPv3.createLocalEngineID());
        final USM usm = new USM(SecurityProtocols.getInstance(), localEngineId, 0);
		usm.setEngineDiscoveryEnabled(true);
        SecurityModels.getInstance().addSecurityModel(usm);
		snmpClient.getMessageDispatcher().addMessageProcessingModel(new MPv3(usm.getLocalEngineID().getValue()));

        final OctetString securityName = new OctetString(v3Credentials.getUserName());
        final OID authProtocol = SnmpAgentV3.getAuthProtocol(v3Credentials.getAuthProtocol());
        final OID privProtocol = SnmpAgentV3.getPrivacyProtocol(v3Credentials.getPrivProtocol());
        final OctetString authPassphrase = new OctetString(v3Credentials.getAuthPassword());
        final OctetString privPassphrase = new OctetString(v3Credentials.getPrivPassword());

		final UsmUser usmUser = new UsmUser(securityName, authProtocol, authPassphrase, privProtocol, privPassphrase);
		usm.addUser(usmUser);
		SecurityModels.getInstance().addSecurityModel(usm);

		snmpClient.listen();

        return snmpClient;
    }

    private PDU buildPDU(VariableBinding var, int pduType, OctetString contextName) throws IOException {
		ScopedPDU pdu = new ScopedPDU();
		pdu.setContextName(contextName);
        pdu.add(var);
        pdu.setType(pduType);

        return pdu;
    }

    private UserTarget buildUserTarget(SnmpAgentV3.Credentials v3Credentials, int port) {
        UserTarget target = new UserTarget();
        target.setSecurityLevel(v3Credentials.getSecurityLevel().getSnmpValue());
        target.setSecurityName(new OctetString(v3Credentials.getUserName()));

        target.setAddress(GenericAddress.parse(String.format("udp:%s/%s", snmpAgentAddress, port)));
        target.setRetries(3);
        target.setTimeout(15000);
        target.setVersion(SnmpConstants.version3);

        return target;
    }
}
