import org.snmp4j.agent.mo.snmp.StorageType;
import org.snmp4j.agent.mo.snmp.VacmMIB;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;

public class SnmpAgentVacmViewTreeFamily {
    private OctetString viewName;
    private OID subtree;
    private OctetString mask;
    private int type;
    private int storageType;

    public SnmpAgentVacmViewTreeFamily() {
        this(new OctetString("fullReadView"), new OID(), new OctetString(),
                VacmMIB.vacmViewIncluded, StorageType.nonVolatile);
    }

    public SnmpAgentVacmViewTreeFamily(OctetString viewName, OID subtree, OctetString mask, int type, int storageType) {
        setViewName(viewName);
        setSubtree(subtree);
        setMask(mask);
        setType(type);
        setStorageType(storageType);
    }

    public SnmpAgentVacmViewTreeFamily setViewName(OctetString viewName) {
        this.viewName = viewName;
        return this;
    }
    public OctetString getViewName() {
        return viewName;
    }

    public SnmpAgentVacmViewTreeFamily setSubtree(OID subtree) {
        this.subtree = subtree;
        return this;
    }
    public OID getSubtree() {
        return subtree;
    }

    public SnmpAgentVacmViewTreeFamily setMask(OctetString mask) {
        this.mask = mask;
        return this;
    }
    public OctetString getMask() {
        return mask;
    }

    public SnmpAgentVacmViewTreeFamily setType(int type) {
        // check the bounds
        if (type < VacmMIB.vacmViewIncluded || type > VacmMIB.vacmViewExcluded) {
            throw new IllegalArgumentException("Invalid type view: " + type);
        }
        this.type = type;
        return this;
    }
    public int getType() {
        return type;
    }

    public SnmpAgentVacmViewTreeFamily setStorageType(int storageType) {
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
