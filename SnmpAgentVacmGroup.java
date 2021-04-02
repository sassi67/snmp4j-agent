package com.compuware.apm.bigtest.extensions.util;

import org.snmp4j.agent.mo.snmp.StorageType;
import org.snmp4j.security.SecurityModel;
import org.snmp4j.smi.OctetString;

public class SnmpAgentVacmGroup {
    private int securityModel;
    private OctetString securityName;
    private OctetString groupName;
    private int storageType;

    public SnmpAgentVacmGroup() {
        this(SecurityModel.SECURITY_MODEL_SNMPv2c, new OctetString("cpublic"),
                new OctetString("v1v2group"), StorageType.nonVolatile);
    }

    public SnmpAgentVacmGroup(int securityModel, OctetString securityName, OctetString groupName, int storageType) {
        setSecurityModel(securityModel);
        setSecurityName(securityName);
        setGroupName(groupName);
        setStorageType(storageType);
    }

    public SnmpAgentVacmGroup setSecurityModel(int securityModel) {
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

    public SnmpAgentVacmGroup setSecurityName(OctetString securityName) {
        this.securityName = securityName;
        return this;
    }

    public OctetString getSecurityName() {
        return securityName;
    }

    public SnmpAgentVacmGroup setGroupName(OctetString groupName) {
        this.groupName = groupName;
        return this;
    }

    public OctetString getGroupName() {
        return groupName;
    }

    public SnmpAgentVacmGroup setStorageType(int storageType) {
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
