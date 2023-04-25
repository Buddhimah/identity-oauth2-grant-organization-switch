/*
 * Copyright (c) 2022, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.grant.organizationswitch;

import com.google.gson.JsonParser;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.xmlsec.signature.impl.PublicKeyBuilder;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.OAuth2TokenValidationService;
import org.wso2.carbon.identity.oauth2.dto.OAuth2ClientApplicationDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.grant.organizationswitch.exception.OrganizationSwitchGrantException;
import org.wso2.carbon.identity.oauth2.grant.organizationswitch.exception.OrganizationSwitchGrantServerException;
import org.wso2.carbon.identity.oauth2.grant.organizationswitch.internal.OrganizationSwitchGrantDataHolder;
import org.wso2.carbon.identity.oauth2.grant.organizationswitch.util.OrganizationSwitchGrantConstants;
import org.wso2.carbon.identity.oauth2.grant.organizationswitch.util.OrganizationSwitchGrantUtil;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AbstractAuthorizationGrantHandler;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.OrganizationManagerImpl;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;

import java.io.ByteArrayInputStream;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Optional;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Base64;
import org.json.JSONObject;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.json.JSONObject;
import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;



import static java.util.Objects.nonNull;
import static java.util.Optional.ofNullable;
import static org.apache.commons.lang.StringUtils.equalsIgnoreCase;
import static org.apache.commons.lang.StringUtils.isBlank;
import static org.wso2.carbon.identity.oauth2.grant.organizationswitch.util.OrganizationSwitchGrantConstants.ORGANIZATION_AUTHENTICATOR;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.ErrorMessages.ERROR_CODE_ERROR_RESOLVING_TENANT_DOMAIN_FROM_ORGANIZATION_DOMAIN;
import static org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants.ErrorMessages.ERROR_CODE_ERROR_RETRIEVING_AUTHENTICATED_USER;
import static org.wso2.carbon.user.core.UserCoreConstants.TENANT_DOMAIN_COMBINER;

/**
 * Implements the AuthorizationGrantHandler for the OrganizationSwitch grant type.
 */
public class OrganizationSwitchGrant extends AbstractAuthorizationGrantHandler {

    private static final Log LOG = LogFactory.getLog(OrganizationSwitchGrant.class);

    public OrganizationManager organizationManager = new OrganizationManagerImpl();

    String publicKeyString = "-----BEGIN CERTIFICATE-----\n" +
            "MIIDqTCCApGgAwIBAgIEYfEVSjANBgkqhkiG9w0BAQsFADBkMQswCQYDVQQGEwJV\n" +
            "UzELMAkGA1UECAwCQ0ExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxDTALBgNVBAoM\n" +
            "BFdTTzIxDTALBgNVBAsMBFdTTzIxEjAQBgNVBAMMCWxvY2FsaG9zdDAeFw0yMjAx\n" +
            "MjYwOTMyNThaFw0yNDA0MzAwOTMyNThaMGQxCzAJBgNVBAYTAlVTMQswCQYDVQQI\n" +
            "DAJDQTEWMBQGA1UEBwwNTW91bnRhaW4gVmlldzENMAsGA1UECgwEV1NPMjENMAsG\n" +
            "A1UECwwEV1NPMjESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF\n" +
            "AAOCAQ8AMIIBCgKCAQEAkdgncoCrz655Lq8pTdX07eoVBjdZDCUE6ueBd0D1hpJ0\n" +
            "/zE3x3Az6tlvzs98PsPuGzaQOMmuLa4qxNJ+OKxJmutDUlClpuvxuf+jyq4gCV5t\n" +
            "EIILWRMBjlBEpJfWm63+VKKU4nvBWNJ7KfhWjl8+DUdNSh2pCDLpUObmb9Kquqc1\n" +
            "x4BgttjN4rx/P+3/v+1jETXzIP1L44yHtpQNv0khYf4j/aHjcEri9ykvpz1mtdac\n" +
            "brKK25N4V1HHRwDqZiJzOCCISXDuqB6wguY/v4n0l1XtrEs7iCyfRFwNSKNrLqr2\n" +
            "3tR1CscmLfbH6ZLg5CYJTD+1uPSx0HMOB4Wv51PbWwIDAQABo2MwYTAUBgNVHREE\n" +
            "DTALgglsb2NhbGhvc3QwHQYDVR0OBBYEFH0KQ3YTZJxTsNsPyrZOSFgXXhG+MB0G\n" +
            "A1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjALBgNVHQ8EBAMCBPAwDQYJKoZI\n" +
            "hvcNAQELBQADggEBAFNJ34CIiIlCxmyp27+KA224LaHVtL5DucFK0P22FQ+QKkON\n" +
            "iUwO70KoVFreBH1Smxu4ePWk6rMZFOM5oL8HXYg3twy+5eGcL3PQd7X5dwAqlViv\n" +
            "zokoi6SDaA/bIG6J/O1U9Qd4XEVJdVuLqjk1+cp70ALt0X6B7sNLfjFcbz3jQULN\n" +
            "nK8HNvqbn7zQuP10s8p5y2qVkPBA/pjigRDsIWR6p78QESF+TaHFjxfcD6f9cnYi\n" +
            "e+yEHERtG8k8x5jLFe+odI1/QGZP8Fy0oKT+E/TJ1FBh4rB1FtKylqGeauPu89Dn\n" +
            "aJ9+kvpNQ94yFmEuhtDByvDijxAqvlin3TPIfy8=\n" +
            "-----END CERTIFICATE-----\n";

    @Override
    public boolean validateGrant(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {



        super.validateGrant(tokReqMsgCtx);

        String token = extractParameter(OrganizationSwitchGrantConstants.Params.TOKEN_PARAM, tokReqMsgCtx);
        String organizationId = extractParameter(OrganizationSwitchGrantConstants.Params.ORG_PARAM, tokReqMsgCtx);
        String name = "";

        // Construct the introspection request
        try {
            // Parse the JWT token
            String[] parts = token.split("\\.");
            String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
            String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);


            // replace with your method to get the public ke


            // Obtain the public key from the X.509 certificate in PEM format
            byte[] publicKeyBytes = publicKeyString.getBytes(StandardCharsets.UTF_8);
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(publicKeyBytes));
            PublicKey publicKey = certificate.getPublicKey();

            Signature verifier = Signature.getInstance("SHA256withRSA");
            byte[] signature = Base64.getUrlDecoder().decode(parts[2]);
            verifier.initVerify(publicKey);
            verifier.update((parts[0] + "." + parts[1]).getBytes());
            boolean verified = verifier.verify(signature);
            System.out.println("Signature Verified: " + verified);

            JSONObject payload = new JSONObject(payloadJson);
            String subject = payload.getString("sub");

            // Print the extracted parameters
            System.out.println("Subject: " + subject);
            name = subject;


            // Extract the claims from the JWT token

        } catch (Exception e) {
            e.printStackTrace();
        }

        String username = name;
        String userId = null;
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName(username);
        authenticatedUser.setUserStoreDomain("PRIMARY");
        authenticatedUser.setTenantDomain(getTenantDomainFromOrganizationId(organizationId));
        RealmService realmService = OrganizationSwitchGrantDataHolder.getInstance().getRealmService();
        int tenantId = 0;
        AbstractUserStoreManager userStoreManager;
        try {
            tenantId = realmService.getTenantManager().getTenantId(authenticatedUser.getTenantDomain());
            userStoreManager
                = (AbstractUserStoreManager) realmService.getTenantUserRealm(tenantId).getUserStoreManager();
            userId = userStoreManager.getUserIDFromUserName(authenticatedUser.getUserName());
        } catch (UserStoreException e) {
            e.printStackTrace();
        }

        if (isBlank(userId)) {
            userId = getUserIdFromAuthorizedUser(authenticatedUser);
        }

        authenticatedUser.setUserId(userId);


        tokReqMsgCtx.setAuthorizedUser(authenticatedUser);

        String[] allowedScopes = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getScope();
        tokReqMsgCtx.setScope(allowedScopes);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Issuing an access token for user: " + authenticatedUser + " with scopes: " +
                    Arrays.toString(tokReqMsgCtx.getScope()));
        }

        return true;
    }

    private String extractParameter(String param, OAuthTokenReqMessageContext tokReqMsgCtx) {

        RequestParameter[] parameters = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getRequestParameters();

        if (parameters != null) {
            for (RequestParameter parameter : parameters) {
                if (param.equals(parameter.getKey())) {
                    if (ArrayUtils.isNotEmpty(parameter.getValue())) {
                        return parameter.getValue()[0];
                    }
                }
            }
        }

        return null;
    }

    /**
     * Validate access token.
     *
     * @param accessToken
     * @return OAuth2TokenValidationResponseDTO of the validated token
     */
    private OAuth2TokenValidationResponseDTO validateToken(String accessToken) {

        OAuth2TokenValidationService oAuth2TokenValidationService = new OAuth2TokenValidationService();
        OAuth2TokenValidationRequestDTO requestDTO = new OAuth2TokenValidationRequestDTO();
        OAuth2TokenValidationRequestDTO.OAuth2AccessToken token = requestDTO.new OAuth2AccessToken();

        token.setIdentifier(accessToken);
        token.setTokenType("bearer");
        requestDTO.setAccessToken(token);

        OAuth2TokenValidationRequestDTO.TokenValidationContextParam contextParam = requestDTO.new
                TokenValidationContextParam();

        OAuth2TokenValidationRequestDTO.TokenValidationContextParam[] contextParams = {contextParam};
        requestDTO.setContext(contextParams);

        OAuth2ClientApplicationDTO clientApplicationDTO = oAuth2TokenValidationService
                .findOAuthConsumerIfTokenIsValid
                        (requestDTO);
        return clientApplicationDTO.getAccessTokenValidationResponse();
    }

    private String getUserIdFromAuthorizedUser(User authorizedUser) throws OrganizationSwitchGrantException {

        try {
            return new AuthenticatedUser(authorizedUser).getUserId();
        } catch (UserIdNotFoundException e) {
            throw OrganizationSwitchGrantUtil.handleServerException(ERROR_CODE_ERROR_RETRIEVING_AUTHENTICATED_USER, e);
        }
    }

    private String getTenantDomainFromOrganizationId(String organizationId) throws OrganizationSwitchGrantException {

        try {
            return organizationManager.resolveTenantDomain(organizationId);
        } catch (OrganizationManagementException e) {
            throw OrganizationSwitchGrantUtil.handleServerException(
                    ERROR_CODE_ERROR_RESOLVING_TENANT_DOMAIN_FROM_ORGANIZATION_DOMAIN, e);
        }
    }

    private Optional<org.wso2.carbon.user.core.common.User> getFederatedUserFromResidentOrganization(String username,
                                                                                                     String organizationId)
            throws OrganizationSwitchGrantServerException {

        try {
            return OrganizationSwitchGrantDataHolder.getInstance().getOrganizationUserResidentResolverService()
                    .resolveUserFromResidentOrganization(username, null, organizationId);
        } catch (OrganizationManagementException e) {
            throw OrganizationSwitchGrantUtil.handleServerException(ERROR_CODE_ERROR_RETRIEVING_AUTHENTICATED_USER, e);
        }
    }

}
