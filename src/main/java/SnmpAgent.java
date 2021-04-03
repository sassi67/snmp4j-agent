import java.io.Closeable;
import java.io.File;
import java.io.IOException;

import org.snmp4j.agent.BaseAgent;
import org.snmp4j.agent.CommandProcessor;
import org.snmp4j.agent.DuplicateRegistrationException;
import org.snmp4j.agent.ManagedObject;
import org.snmp4j.agent.mo.snmp.SnmpCommunityMIB;
import org.snmp4j.agent.mo.snmp.SnmpNotificationMIB;
import org.snmp4j.agent.mo.snmp.SnmpTargetMIB;
import org.snmp4j.mp.MPv3;
import org.snmp4j.security.USM;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.UdpAddress;
import org.snmp4j.transport.DefaultUdpTransportMapping;

public abstract class SnmpAgent extends BaseAgent implements Closeable {

	private int port = 0;
	private final String snmpBootCounterFile = "bootCounterFile.txt";
	private final String snmpConfigFile = "configFile.txt";
	private final ManagedObject[] objects;

	protected SnmpAgentVacmGroup vacmGroup = null;
	protected SnmpAgentVacmAccess vacmAccess = null;
	protected SnmpAgentVacmViewTreeFamily vacmReadView = null;
	protected SnmpAgentVacmViewTreeFamily vacmWriteView = null;
	protected SnmpAgentVacmViewTreeFamily vacmNotifyView = null;

	public SnmpAgent(ManagedObject... objects) {
		super(new File(System.getProperty("user.home") + "/bootCounterFile.txt"),
				new File(System.getProperty("user.home") + "/configFile.txt"),
				new CommandProcessor(new OctetString(MPv3.createLocalEngineID())));
		this.objects = objects;
	}

	// bootCounterFile and configFile are generated when SnmpAgent shuts down
	public String getSnmpBootCounterFile() {
		return snmpBootCounterFile;
	}

	public String getSnmpConfigFile() {
		return snmpConfigFile;
	}

	public SnmpAgent setVacmGroup(SnmpAgentVacmGroup vacmGroup) {
		this.vacmGroup = vacmGroup;
		return this;
	}

	public SnmpAgent setVacmAccess(SnmpAgentVacmAccess vacmAccess) {
		this.vacmAccess = vacmAccess;
		return this;
	}

	public SnmpAgent setVacmReadView(SnmpAgentVacmViewTreeFamily vacmReadView) {
		this.vacmReadView = vacmReadView;
		return this;
	}

	public SnmpAgent setVacmWriteView(SnmpAgentVacmViewTreeFamily vacmWriteView) {
		this.vacmWriteView = vacmWriteView;
		return this;
	}

	public SnmpAgent setVacmNotifyView(SnmpAgentVacmViewTreeFamily vacmNotifyView) {
		this.vacmNotifyView = vacmNotifyView;
		return this;
	}

	protected void restart() throws IOException {
		close();
		start();
	}

	public int getPort() {
		return port;
	}

	@Override
	public void close() {
		stop();
	}

	@Override
	protected void registerManagedObjects() {
		getSnmpv2MIB().unregisterMOs(this.server, getContext(getSnmpv2MIB()));

		for (ManagedObject object : objects) {
			try {
				this.server.register(object, null);
			} catch (DuplicateRegistrationException e) {
				throw new RuntimeException(e);
			}
		}
	}

	@Override
	protected void unregisterManagedObjects() {
		for (ManagedObject object : objects) {
			this.server.unregister(object, null);
		}
	}

	@Override
	protected void initTransportMappings() throws IOException {
		DefaultUdpTransportMapping mapping;
		if (this.port == 0) {
			mapping = new DefaultUdpTransportMapping();
		} else {
			mapping = new DefaultUdpTransportMapping(new UdpAddress("0.0.0.0/" + this.port), true);
		}
		transportMappings = new DefaultUdpTransportMapping[] { mapping };
		this.port = mapping.getListenAddress().getPort();
	}

	@Override
	protected void addUsmUser(USM usm) {}

	@Override
	protected void addNotificationTargets(SnmpTargetMIB targetMIB, SnmpNotificationMIB notificationMIB) {}

	@Override
	protected void addCommunities(SnmpCommunityMIB communityMIB) {}

	public abstract void start() throws IOException;
}