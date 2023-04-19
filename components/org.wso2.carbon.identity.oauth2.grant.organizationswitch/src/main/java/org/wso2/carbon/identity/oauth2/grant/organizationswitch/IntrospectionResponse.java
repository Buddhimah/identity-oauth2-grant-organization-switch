package org.wso2.carbon.identity.oauth2.grant.organizationswitch;

/**
 * This is a model information returned from the toke introspection.
 */
public class IntrospectionResponse {

    private boolean isActive;
    private String username;
    private String tenantDomain;

    public boolean isActive() {

        return isActive;
    }

    public void setActive(boolean active) {

        isActive = active;
    }

    public String getUsername() {

        return username;
    }

    public void setUsername(String username) {

        this.username = username;
    }

    public String getTenantDomain() {

        return tenantDomain;
    }

    public void setTenantDomain(String tenantDomain) {

        this.tenantDomain = tenantDomain;
    }
}
