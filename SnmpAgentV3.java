package com.compuware.apm.bigtest.extensions.util;

import java.io.IOException;

import org.snmp4j.agent.ManagedObject;
import org.snmp4j.agent.mo.snmp.SnmpCommunityMIB;
import org.snmp4j.agent.mo.snmp.StorageType;
import org.snmp4j.agent.mo.snmp.VacmMIB;
import org.snmp4j.security.AuthHMAC128SHA224;
import org.snmp4j.security.AuthHMAC192SHA256;
import org.snmp4j.security.AuthHMAC256SHA384;
import org.snmp4j.security.AuthHMAC384SHA512;
import org.snmp4j.security.AuthMD5;
import org.snmp4j.security.AuthSHA;
import org.snmp4j.security.PrivAES128;
import org.snmp4j.security.PrivAES192;
import org.snmp4j.security.PrivAES256;
import org.snmp4j.security.PrivDES;
import org.snmp4j.security.SecurityLevel;
import org.snmp4j.security.SecurityModel;
import org.snmp4j.security.SecurityProtocols;
import org.snmp4j.security.USM;
import org.snmp4j.security.UsmUser;
import org.snmp4j.security.nonstandard.PrivAES192With3DESKeyExtension;
import org.snmp4j.security.nonstandard.PrivAES256With3DESKeyExtension;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;

public class SnmpAgentV3 extends SnmpAgent {

    public static class Credentials {
        private String userName;
        private SecurityLevel securityLevel;
        private String authProtocol;
        private String authPassword;
        private String privProtocol;
        private String privPassword;

        private Credentials() {}
        public Credentials(String userName, SecurityLevel securityLevel, String authProtocol, String authPassword,
                           String privProtocol, String privPassword) {
            this.userName = userName;
            this.securityLevel = securityLevel;
            this.authProtocol = authProtocol;
            this.authPassword = authPassword;
            this.privProtocol = privProtocol;
            this.privPassword = privPassword;
        }

        public String getUserName() {
            return userName;
        }

        public void setUserName(String userName) {
            this.userName = userName;
        }

        public SecurityLevel getSecurityLevel() {
            return securityLevel;
        }

        public void setSecurityLevel(SecurityLevel securityLevel) {
            this.securityLevel = securityLevel;
        }

        public String getAuthProtocol() {
            return authProtocol;
        }

        public void setAuthProtocol(String authProtocol) {
            if (this.authProtocol != authProtocol) {
				this.authProtocol = authProtocol;
			}
        }

        public String getAuthPassword() {
            return authPassword;
        }

        public void setAuthPassword(String authPassword) {
            this.authPassword = authPassword;
        }

        public String getPrivProtocol() {
            return privProtocol;
        }

        public void setPrivProtocol(String privProtocol) {
            this.privProtocol = privProtocol;
        }

        public String getPrivPassword() {
            return privPassword;
        }

        public void setPrivPassword(String privPassword) {
            this.privPassword = privPassword;
        }

    }

    private final Credentials credentials;
	private final OctetString contextName;

    public SnmpAgentV3(Credentials credentials, ManagedObject... objects) throws IOException {
        super(objects);
        this.credentials = credentials;
        this.contextName = new OctetString();//"v3context"
        start();
    }

    public static OID getAuthProtocol(String authProtocol) {
        switch (authProtocol) {
            case "MD5":
                return AuthMD5.ID;
            case "SHA":
                return AuthSHA.ID;
            case "SHA224":
                return AuthHMAC128SHA224.ID;
            case "SHA256":
                return AuthHMAC192SHA256.ID;
            case "SHA384":
                return AuthHMAC256SHA384.ID;
            case "SHA512":
                return AuthHMAC384SHA512.ID;
            default:
                return null; // this user only supports unauthenticated messages
        }
    }

    public static OID getPrivacyProtocol(String privProtocol) {
        switch (privProtocol) {
            case "DES":
                return PrivDES.ID;
            case "AES":
                return PrivAES128.ID;
            case "AES192":
                return PrivAES192.ID;
            case "AES256":
                return PrivAES256.ID;
            case "AES192C":
                return PrivAES192With3DESKeyExtension.ID;
            case "AES256C":
                return PrivAES256With3DESKeyExtension.ID;
            default:
                return null; // TODO
        }
    }

    public OctetString getContextName() {
    	return this.contextName;
	}

	public void setUserName(String userName) throws IOException {
    	if (credentials.getUserName() != userName) {
    		credentials.setUserName(userName);
			restart();
		}
	}

    @Override
    protected void addUsmUser(USM usm) {
        UsmUser user = new UsmUser(new OctetString(credentials.userName),
                getAuthProtocol(credentials.authProtocol),
                new OctetString(credentials.authPassword),
                getPrivacyProtocol(credentials.privProtocol),
                new OctetString(credentials.privPassword));
        usm.addUser(user.getSecurityName(), usm.getLocalEngineID(), user);
    }

	@Override
    protected void addViews(VacmMIB vacmMIB) {
		if (this.vacmGroup == null) {
			this.vacmGroup = new SnmpAgentVacmGroup()
					.setSecurityModel(SecurityModel.SECURITY_MODEL_USM)
					.setSecurityName(new OctetString(credentials.getUserName()))
					.setGroupName(new OctetString("v3group"))
					.setStorageType(StorageType.nonVolatile);
		}
        vacmMIB.addGroup(
				this.vacmGroup.getSecurityModel(),
				this.vacmGroup.getSecurityName(),
				this.vacmGroup.getGroupName(),
				this.vacmGroup.getStorageType());
		if (this.vacmAccess == null) {
			this.vacmAccess = new SnmpAgentVacmAccess()
					.setGroupName(this.vacmGroup.getGroupName())
					.setContextPrefix(this.contextName)
					.setSecurityModel(this.vacmGroup.getSecurityModel())
					.setSecurityLevel(this.credentials.getSecurityLevel())
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

    @Override
    protected void addCommunities(SnmpCommunityMIB communityMIB) {
		// Important! Keep this empty: it's valid only for Snmp V2
	}

    @Override
    public void start() throws IOException {
        init();
        addShutdownHook();
		getServer().addContext(contextName);
        finishInit();
		SecurityProtocols.getInstance().addDefaultProtocols();
        run();
        sendColdStartNotification();
    }
}
