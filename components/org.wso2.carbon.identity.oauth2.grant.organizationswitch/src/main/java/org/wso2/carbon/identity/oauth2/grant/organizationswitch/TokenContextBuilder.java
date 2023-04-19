/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.com). All Rights Reserved.
 *
 * This software is the property of WSO2 Inc. and its suppliers, if any.
 * Dissemination of any information or reproduction of any material contained
 * herein in any form is strictly forbidden, unless permitted by WSO2 expressly.
 * You may not alter or remove any copyright or other notice from copies of this content.
 */

package org.wso2.carbon.identity.oauth2.grant.organizationswitch;


import com.nimbusds.oauth2.sdk.ParseException;
import org.wso2.carbon.identity.oauth2.grant.organizationswitch.IntrospectionResponse;

import java.io.IOException;

/**
 * Service interface for token validator.
 */
public interface TokenContextBuilder {

    /**
     * Validate the access token through wso2 Identity Server Oauth2 introspection endpoint.
     *
     * @param apiAccessToken Access token provided by API consumer
     * @return The introspection endpoint returned by the server.
     * @throws IOException    If an error occurred while validating the token.
     */
    IntrospectionResponse getTokenContext(String apiAccessToken) throws ParseException,IOException;

    /**
     * Validate the access token through wso2 Identity Server Oauth2 introspection endpoint.
     *
     * @param apiAccessToken Access token provided by API consumer.
     * @param tenantDomain   Tenant Domain of the user.
     * @return The introspection endpoint returned by the server.
     * @throws IOException    If an error occurred while validating the token.
     */
    default IntrospectionResponse getTokenContext(String apiAccessToken, String tenantDomain) throws ParseException,
            IOException {

        return getTokenContext(apiAccessToken,tenantDomain);
    }
}
