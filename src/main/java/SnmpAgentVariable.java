import org.snmp4j.agent.mo.snmp.RowStatus;
import org.snmp4j.agent.mo.snmp.StorageType;
import org.snmp4j.smi.Integer32;
import org.snmp4j.smi.OctetString;

public class SnmpAgentVariable {
    private OctetString variableName;
    // members to make a Variable object
    private OctetString community;
    private OctetString securityName;
    private OctetString localEngineID;
    private OctetString contextName;
    private OctetString transportTag;
    private Integer32 storageType;
    private Integer32 rowStatus;

    public SnmpAgentVariable() {
        this(new OctetString("public2public"), new OctetString("community"),
                new OctetString("cpublic"), null, new OctetString("community"),
                new OctetString(), new Integer32(StorageType.nonVolatile), new Integer32(RowStatus.active));
    }

    public SnmpAgentVariable(OctetString variableName, OctetString community, OctetString securityName,
                             OctetString localEngineID, OctetString contextName, OctetString transportTag,
                             Integer32 storageType, Integer32 rowStatus) {
        setVariableName(variableName);
        setCommunity(community);
        setSecurityName(securityName);
        setLocalEngineID(localEngineID);
        setContextName(contextName);
        setTransportTag(transportTag);
        setStorageType(storageType);
        setRowStatus(rowStatus);
    }

    public SnmpAgentVariable setVariableName(OctetString variableName) {
        this.variableName = variableName;
        return this;
    }
    public OctetString getVariableName() {
        return variableName;
    }

    public SnmpAgentVariable setCommunity(OctetString community) {
        this.community = community;
        return this;
    }
    public OctetString getCommunity() {
        return community;
    }

    public SnmpAgentVariable setSecurityName(OctetString securityName) {
        this.securityName = securityName;
        return this;
    }
    public OctetString getSecurityName() {
        return securityName;
    }

    public SnmpAgentVariable setLocalEngineID(OctetString localEngineID) {
        this.localEngineID = localEngineID;
        return this;
    }
    public OctetString getLocalEngineID() {
        return localEngineID;
    }

    public SnmpAgentVariable setContextName(OctetString contextName) {
        this.contextName = contextName;
        return this;
    }
    public OctetString getContextName() {
        return contextName;
    }

    public SnmpAgentVariable setTransportTag(OctetString transportTag) {
        this.transportTag = transportTag;
        return this;
    }
    public OctetString getTransportTag() {
        return transportTag;
    }

    public SnmpAgentVariable setStorageType(Integer32 storageType) {
        // check the bounds
        final int storageTypeInt = storageType.toInt();
        if (storageTypeInt < StorageType.other || storageTypeInt > StorageType.readOnly) {
            throw new IllegalArgumentException("Invalid storage type: " + storageTypeInt);
        }
        this.storageType = storageType;
        return this;
    }
    public Integer32 getStorageType() {
        return storageType;
    }

    public SnmpAgentVariable setRowStatus(Integer32 rowStatus) {
        // check the bounds
        final int rowStatusInt = rowStatus.toInt();
        if (rowStatusInt < RowStatus.notExistant || rowStatusInt > RowStatus.destroy) {
            throw new IllegalArgumentException("Invalid row status: " + rowStatusInt);
        }
        this.rowStatus = rowStatus;
        return this;
    }

    public Integer32 getRowStatus() {
        return rowStatus;
    }
}
