import org.snmp4j.agent.mo.snmp.StorageType;
import org.snmp4j.agent.security.MutableVACM;
import org.snmp4j.security.SecurityLevel;
import org.snmp4j.security.SecurityModel;
import org.snmp4j.smi.OctetString;

public class SnmpAgentVacmAccess {
    private OctetString groupName;
    private OctetString contextPrefix;
    private int securityModel;
    private SecurityLevel securityLevel;
    private int match;
    private OctetString readView;
    private OctetString writeView;
    private OctetString notifyView;
    private int storageType;

    public SnmpAgentVacmAccess() {
        this(new OctetString("v1v2group"), new OctetString("v2context"),
                SecurityModel.SECURITY_MODEL_ANY, SecurityLevel.noAuthNoPriv, MutableVACM.VACM_MATCH_EXACT,
                new OctetString("fullReadView"), new OctetString("fullWriteView"),
                new OctetString("fullNotifyView"), StorageType.nonVolatile);
    }

    public SnmpAgentVacmAccess(OctetString groupName, OctetString contextPrefix,
                               int securityModel, SecurityLevel securityLevel, int match,
                               OctetString readView, OctetString writeView, OctetString notifyView, int storageType) {
        setGroupName(groupName);
        setContextPrefix(contextPrefix);
        setSecurityModel(securityModel);
        setSecurityLevel(securityLevel);
        setMatch(match);
        setReadView(readView);
        setWriteView(writeView);
        setNotifyView(notifyView);
        setStorageType(storageType);
    }

    public SnmpAgentVacmAccess setGroupName(OctetString groupName) {
        this.groupName = groupName;
        return this;
    }
    public OctetString getGroupName() {
        return groupName;
    }

    public SnmpAgentVacmAccess setContextPrefix(OctetString contextPrefix) {
        this.contextPrefix = contextPrefix;
        return this;
    }
    public OctetString getContextPrefix() {
        return contextPrefix;
    }

    public SnmpAgentVacmAccess setSecurityModel(int securityModel) {
        // check the bounds
        if (securityModel < SecurityModel.SECURITY_MODEL_ANY || securityModel > SecurityModel.SECURITY_MODEL_TSM) {
            throw new IllegalArgumentException("Invalid security model: " + securityModel);
        }
        this.securityModel = securityModel;
        return this;
    }
    public int getSecurityModel() {
        return securityModel;
    }

    public SnmpAgentVacmAccess setSecurityLevel(SecurityLevel securityLevel) {
        this.securityLevel = securityLevel;
        return this;
    }
    public SecurityLevel getSecurityLevel() {
        return securityLevel;
    }

    public SnmpAgentVacmAccess setMatch(int match) {
        // check the bounds
        if (match < MutableVACM.VACM_MATCH_EXACT || match > MutableVACM.VACM_MATCH_PREFIX) {
            throw new IllegalArgumentException("Invalid match model: " + match);
        }
        this.match = match;
        return this;
    }
    public int getMatch() {
        return match;
    }

    public SnmpAgentVacmAccess setReadView(OctetString readView) {
        this.readView = readView;
        return this;
    }
    public OctetString getReadView() {
        return readView;
    }

    public SnmpAgentVacmAccess setWriteView(OctetString writeView) {
        this.writeView = writeView;
        return this;
    }
    public OctetString getWriteView() {
        return writeView;
    }

    public SnmpAgentVacmAccess setNotifyView(OctetString notifyView) {
        this.notifyView = notifyView;
        return this;
    }
    public OctetString getNotifyView() {
        return notifyView;
    }

    public SnmpAgentVacmAccess setStorageType(int storageType) {
        // check the bounds
        if (storageType < StorageType.other || storageType > StorageType.readOnly) {
            throw new IllegalArgumentException("Invalid storage type: " + storageType);
        }
        this.storageType = storageType;
        return this;
    }

    public int getStorageType() {
        return storageType;
    }
}
