package org.wso2.carbon.identity.oauth2.grant.organizationswitch;

import com.hazelcast.org.snakeyaml.engine.v1.api.lowlevel.Parse;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenIntrospectionRequest;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.Token;

import javax.net.ssl.SSLSocketFactory;

public class AbstractTokenContextBuilder implements TokenContextBuilder {

    private static final Logger log = LogManager.getLogger(AbstractTokenContextBuilder.class);

    private String tenantPlaceHolder = "{tenant_domain}";
    private String tenantPath = "/t/";


    protected String introspectUrl;

    protected String username;

    protected String password;

    protected String clientId = "############";

    protected String clientSecret = "#############";

    protected SSLSocketFactory sslSocketFactory;

    protected boolean trustAnyCert;


    @Override
    public IntrospectionResponse getTokenContext(String apiAccessToken) throws IOException {
        return null;
    }

    @Override
    public IntrospectionResponse getTokenContext(String apiAccessToken, String tenantDomain) throws ParseException, IOException {
        return introspectToken("https://localhost:9443/t/testasgardeo2/oauth2/introspect", apiAccessToken);
    }


    private IntrospectionResponse introspectToken(String introspectUrl, String apiAccessToken) throws ParseException,IOException {

        if (log.isDebugEnabled()) {
            log.debug("Token introspection started.");
        }

        URI endpoint = URI.create(introspectUrl);
        String authHeader = clientId + ":" + clientSecret;
        byte[] authHeaderInBytes = authHeader.getBytes(StandardCharsets.UTF_8);
        Token accessToken = new BearerAccessToken(apiAccessToken);
        TokenIntrospectionRequest request = new TokenIntrospectionRequest(endpoint, accessToken);
        HTTPRequest httpRequest = request.toHTTPRequest();

        httpRequest.setSSLSocketFactory(sslSocketFactory);
        if (trustAnyCert) {
            httpRequest.setHostnameVerifier(NoopHostnameVerifier.INSTANCE);
        }
        httpRequest.setAuthorization("Basic " + new String(Base64.getEncoder().encode(authHeaderInBytes),
                StandardCharsets.UTF_8));
        HTTPResponse httpResponse = httpRequest.send();
        return buildIntrospectionResponse(httpResponse);
    }

    private IntrospectionResponse buildIntrospectionResponse(HTTPResponse httpResponse) throws ParseException,
            IOException {

        IntrospectionResponse introspectionResponse = new IntrospectionResponse();
        introspectionResponse.setActive(Boolean.parseBoolean(
                httpResponse.getContentAsJSONObject().get("active").toString()));


        if (!introspectionResponse.isActive()) {
            if (log.isDebugEnabled()) {
                log.debug("The provided token is not 'active'");
            }
            // If active state is false, then username information will not be in the response.
            return introspectionResponse;
        }

        String username = httpResponse.getContentAsJSONObject().get(
                "username").toString();

        // Extract the username without the tenant domain.
        introspectionResponse.setUsername(username.substring(0, username.lastIndexOf("@")));
        // Extract the tenant domain.
        introspectionResponse.setTenantDomain(username.substring(username.lastIndexOf("@") + 1));
        if (log.isDebugEnabled()) {
            log.debug("Token introspection completed successfully.");
        }
        return introspectionResponse;

    }
    }




