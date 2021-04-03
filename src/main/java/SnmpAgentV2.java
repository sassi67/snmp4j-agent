import java.io.IOException;

import org.snmp4j.agent.ManagedObject;
import org.snmp4j.agent.mo.snmp.SnmpCommunityMIB;
import org.snmp4j.agent.mo.snmp.VacmMIB;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.Variable;

public class SnmpAgentV2 extends SnmpAgent{
	private String community;
	private SnmpAgentVariable addCommunity = null;

	public SnmpAgentV2(String community, ManagedObject... objects) throws IOException {
		super(objects);
		this.community = community;
		start();
	}

	public SnmpAgent setAddCommunity(SnmpAgentVariable addCommunity) {
		this.addCommunity = addCommunity;
		return this;
	}

	public void setCommunity(String community) throws IOException {
		if (community != this.community) {
			this.community = community;
			this.addCommunity.setCommunity(new OctetString(this.community));
			restart();
		}
	}

	@Override
	protected void addCommunities(SnmpCommunityMIB communityMIB) {
		if (this.addCommunity == null) {
			this.addCommunity = new SnmpAgentVariable()
					.setCommunity(new OctetString(this.community))
					.setContextName(new OctetString(this.community));
		}
		this.addCommunity.setLocalEngineID(getAgent().getContextEngineID()); // important!

		Variable[] com2sec = new Variable[] {
				this.addCommunity.getCommunity(),		// community name
				this.addCommunity.getSecurityName(),    // security name
				this.addCommunity.getLocalEngineID(),	// local engine ID
				this.addCommunity.getContextName(),		// default context name
				this.addCommunity.getTransportTag(),    // transport tag
				this.addCommunity.getStorageType(),     // storage type
				this.addCommunity.getRowStatus()        // row status
		};
		SnmpCommunityMIB.SnmpCommunityEntryRow row = communityMIB.getSnmpCommunityEntry().createRow(
				this.addCommunity.getVariableName().toSubIndex(true), com2sec);
		communityMIB.getSnmpCommunityEntry().addRow(row);
	}

	@Override
	protected void addViews(VacmMIB vacmMIB) {
		if (this.vacmGroup == null) {
			this.vacmGroup =  new SnmpAgentVacmGroup();
		}
		vacmMIB.addGroup(
				this.vacmGroup.getSecurityModel(),
				this.vacmGroup.getSecurityName(),
				this.vacmGroup.getGroupName(),
				this.vacmGroup.getStorageType());

		if (this.vacmAccess == null) {
			this.vacmAccess = new SnmpAgentVacmAccess()
					.setGroupName(this.vacmGroup.getGroupName())
					.setContextPrefix(new OctetString(this.community))
					.setStorageType(this.vacmGroup.getStorageType());
		}
		vacmMIB.addAccess(
				this.vacmAccess.getGroupName(),
				this.vacmAccess.getContextPrefix(),
				this.vacmAccess.getSecurityModel(),
				this.vacmAccess.getSecurityLevel().getSnmpValue(),
				this.vacmAccess.getMatch() ,
				this.vacmAccess.getReadView(),
				this.vacmAccess.getWriteView(),
				this.vacmAccess.getNotifyView(),
				this.vacmAccess.getStorageType());

		if (this.vacmReadView == null) {
			this.vacmReadView = new SnmpAgentVacmViewTreeFamily()
					.setViewName(this.vacmAccess.getReadView())
					.setStorageType(this.vacmAccess.getStorageType());
		}
		vacmMIB.addViewTreeFamily(
				this.vacmReadView.getViewName(),
				this.vacmReadView.getSubtree(),
				this.vacmReadView.getMask(),
				this.vacmReadView.getType(),
				this.vacmReadView.getStorageType());

		if (this.vacmWriteView == null) {
			this.vacmWriteView = new SnmpAgentVacmViewTreeFamily()
					.setViewName(new OctetString("fullWriteView"))
					.setStorageType(this.vacmAccess.getStorageType());
		}
		vacmMIB.addViewTreeFamily(
				this.vacmWriteView.getViewName(),
				this.vacmWriteView.getSubtree(),
				this.vacmWriteView.getMask(),
				this.vacmWriteView.getType(),
				this.vacmWriteView.getStorageType());

		if (this.vacmNotifyView == null) {
			this.vacmNotifyView = new SnmpAgentVacmViewTreeFamily()
					.setViewName(new OctetString("fullNotifyView"))
					.setStorageType(this.vacmAccess.getStorageType());
		}
		vacmMIB.addViewTreeFamily(
				this.vacmNotifyView.getViewName(),
				this.vacmNotifyView.getSubtree(),
				this.vacmNotifyView.getMask(),
				this.vacmNotifyView.getType(),
				this.vacmNotifyView.getStorageType());
	}

	public void start() throws IOException {
		init();
		addShutdownHook();
		getServer().addContext(new OctetString(this.community));
		finishInit();
		run();
		sendColdStartNotification();
	}
}
