/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.brooklyn.rest.security.provider;

import java.io.IOException;
import java.util.*;

import javax.servlet.ServletException;
import javax.servlet.http.HttpSession;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import com.google.common.base.Preconditions;
import org.apache.brooklyn.api.mgmt.ManagementContext;
import org.apache.brooklyn.rest.filter.BrooklynSecurityProviderFilterHelper;
import org.apache.brooklyn.util.exceptions.Exceptions;
import org.apache.brooklyn.util.text.Identifiers;
import org.apache.brooklyn.util.text.Strings;
import org.apache.brooklyn.util.time.Duration;
import org.apache.brooklyn.util.yaml.Yamls;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.eclipse.jetty.http.HttpHeader;
import org.eclipse.jetty.server.HttpChannel;
import org.eclipse.jetty.server.HttpConnection;
import org.eclipse.jetty.server.Request;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.annotations.Beta;

import static org.apache.brooklyn.rest.BrooklynWebConfig.*;

/** Configurable OAuth redirect security provider
 * 
 *  Redirects all inbound requests to an oath web server unless a session token is specified. */
@Beta  // work in progress
public class OauthSecurityProvider implements SecurityProvider {

    public static final Logger log = LoggerFactory.getLogger(OauthSecurityProvider.class);

    private static final String OAUTH_ACCESS_TOKEN_SESSION_KEY = "org.apache.brooklyn.security.oauth.access_token";
    private static final String OAUTH_ACCESS_TOKEN_EXPIRY_UTC_KEY = "org.apache.brooklyn.security.oauth.access_token_expiry_utc";
    
    private static final String OAUTH_AUTH_CODE_PARAMETER_FROM_USER = "code";
    private static final String OAUTH_AUTH_CODE_PARAMETER_FOR_SERVER = OAUTH_AUTH_CODE_PARAMETER_FROM_USER;
    
    // tempting to use getJettyRequest().getRequestURL().toString();
    // but some oauth providers require this to be declared
    private String callbackUri;
    private String accessTokenResponseKey = "access_token";
    private String audience = "audience";
    private Duration validity = Duration.hours(1);
    
    // google test data - hard-coded for now
    private String uriGetToken;
    private String uriAuthorize;
    private String uriTokenInfo;
    private String clientId;
    private String clientSecret;

    private Set<String> authorizedUsers;
    private Set<String> authorizedDomains;
    
    protected final ManagementContext mgmt;

    public OauthSecurityProvider(ManagementContext mgmt) {
        this.mgmt = mgmt;
        initialize();
    }

    private synchronized void initialize() {

        uriGetToken = mgmt.getConfig().getConfig(SECURITY_OAUTH_TOKEN_URL);
        Preconditions.checkNotNull(uriGetToken, "URI to get token must be set: "+SECURITY_OAUTH_TOKEN_URL.getName());

        uriAuthorize = mgmt.getConfig().getConfig(SECURITY_OAUTH_AUTHORIZE_URL);
        Preconditions.checkNotNull(uriAuthorize, "URI to authorize must be set: "+SECURITY_OAUTH_AUTHORIZE_URL.getName());

        uriTokenInfo = mgmt.getConfig().getConfig(SECURITY_OAUTH_VALIDATE_URL);
        Preconditions.checkNotNull(uriTokenInfo, "URI to validate the current token must be set: "+SECURITY_OAUTH_VALIDATE_URL.getName());

        clientId = mgmt.getConfig().getConfig(SECURITY_OAUTH_CLIENT_ID);
        Preconditions.checkNotNull(clientId, "Client ID must be set: "+SECURITY_OAUTH_CLIENT_ID.getName());

        clientSecret = mgmt.getConfig().getConfig(SECURITY_OAUTH_CLIENT_SECRET);
        Preconditions.checkNotNull(clientSecret, "Client secret must be set: "+SECURITY_OAUTH_CLIENT_SECRET.getName());

        callbackUri = mgmt.getConfig().getConfig(SECURITY_OAUTH_CALLBACK);
        Preconditions.checkNotNull(callbackUri, "Callback URL must be set: "+SECURITY_OAUTH_CALLBACK.getName());

        String authorizedUsersReaded= mgmt.getConfig().getConfig(SECURITY_OAUTH_AUTHORIZED_USERS);
        if(Strings.isNonBlank(authorizedUsersReaded)){
            authorizedUsers = new HashSet<>(Arrays.asList(authorizedUsersReaded.split("\\s*,\\s*")));
        }

        String authorizedDomainsReaded= mgmt.getConfig().getConfig(SECURITY_OAUTH_AUTHORIZED_DOMAINS);
        if(Strings.isNonBlank(authorizedDomainsReaded)){
            authorizedDomains = new HashSet<>(Arrays.asList(authorizedDomainsReaded.split("\\s*,\\s*")));
        }
    }
    
    @Override
    public boolean isAuthenticated(HttpSession session) {
        // TODO tidy log messages
        log.info("isAuthenticated 1 "+getJettyRequest().getRequestURI()+" "+session+" ... "+this);
        if(session==null || Strings.isBlank((String) session.getAttribute(OAUTH_ACCESS_TOKEN_SESSION_KEY))) return false;

        try {
            return validateTokenAgainstOauthServer((String) session.getAttribute(OAUTH_ACCESS_TOKEN_SESSION_KEY),session);
        } catch (Exception e) {
            return  false;
        }
    }

    @Override
    public boolean authenticate(HttpSession session, String user, String password) throws SecurityProviderDeniedAuthentication {
        log.info("authenticate "+session+" "+user);
        
        if (isAuthenticated(session)) {
            return true;
        }
        
        Request request = getJettyRequest();
        // Redirection from the authenticator server
        String code = request.getParameter(OAUTH_AUTH_CODE_PARAMETER_FROM_USER);
        // Getting token, if exists, from the current session
        String token = (String) request.getSession().getAttribute(OAUTH_ACCESS_TOKEN_SESSION_KEY);
        
        try {
            if (Strings.isNonBlank(code)) {
                return retrieveTokenForAuthCodeFromOauthServer(session, code);
            } else if (Strings.isNonBlank(token)) {
                // they have a token but no auth code and not or no longer authenticated; 
                // we need to check that the token is still valid
                return validateTokenAgainstOauthServer(token,session);
            } else {
                // no token or code; the user needs to log in
                return redirectUserToOauthLoginUi();
            }
        } catch (SecurityProviderDeniedAuthentication e) {
            throw e;
        } catch (Exception e) {
            log.warn("Error performing OAuth: "+e, e);
            throw Exceptions.propagate(e);
        }
    }

    @Override
    public boolean logout(HttpSession session) {
        log.info("logout");
        session.removeAttribute(OAUTH_ACCESS_TOKEN_SESSION_KEY);
        session.removeAttribute(OAUTH_ACCESS_TOKEN_EXPIRY_UTC_KEY);
        return true;
    }
    
    @Override
    public boolean requiresUserPass() {
        return false;
    }

    private boolean retrieveTokenForAuthCodeFromOauthServer(HttpSession session, String code) throws ClientProtocolException, IOException, ServletException, SecurityProviderDeniedAuthentication {
        // get the access token by post to Google
        HashMap<String, String> params = new HashMap<String, String>();
        params.put(OAUTH_AUTH_CODE_PARAMETER_FOR_SERVER, code);
        params.put("client_id", clientId);
        params.put("client_secret", clientSecret);
        params.put("redirect_uri", callbackUri);
        params.put("grant_type", "authorization_code");

        String body = post(uriGetToken, params);

        Map<?,?> jsonObject = null;

        // get the access token from json and request info from Google
        try {
            jsonObject = (Map<?,?>) Yamls.parseAll(body).iterator().next();
            log.info("Parsed '"+body+"' as "+jsonObject);
        } catch (Exception e) {
            Exceptions.propagateIfFatal(e);
            log.info("Unable to parse: '"+body+"'");
            // throw new RuntimeException("Unable to parse json " + body);
            return redirectUserToOauthLoginUi();
        }

        // TODO validate
        
        // Put token in session
        String accessToken = (String) jsonObject.get(accessTokenResponseKey);
        if(validateTokenAgainstOauthServer(accessToken,session)){
            session.setAttribute(OAUTH_ACCESS_TOKEN_SESSION_KEY, accessToken);
        }


        
        return true;
    }

    private boolean validateTokenAgainstOauthServer(String token, HttpSession session) throws ClientProtocolException, IOException, SecurityProviderDeniedAuthentication {
        // TODO support validation, and run periodically
        
        HashMap<String, String> params = new HashMap<String, String>();
        params.put(accessTokenResponseKey, token);

        String body = post(uriTokenInfo, params);

        Map<?,?> jsonObject = null;
        // get the access token from json and request info from Google
        try {
            jsonObject = (Map<?,?>) Yamls.parseAll(body).iterator().next();
            @SuppressWarnings("unchecked")
            String email = Strings.toString( ((Map<String,Object>) Yamls.parseAll(body).iterator().next()).get("email") );
            if(!isEmailAuthorized(email)){
                throw new SecurityProviderDeniedAuthentication();
            }
//            String user = Strings.toString( ((Map<String,Object>) Yamls.parseAll(body).iterator().next()).get("name") );
            session.setAttribute(BrooklynSecurityProviderFilterHelper.AUTHENTICATED_USER_SESSION_ATTRIBUTE, email);
            log.trace("Parsed '{}' as {}", body ,jsonObject);
        } catch (Exception e) {
            Exceptions.propagateIfFatal(e);
            log.trace("Unable to parse: '{}'",body);
            throw new RuntimeException("Unable to parse json " + body, e);
        }

        if (!clientId.equals(jsonObject.get(audience))) {
            log.trace("Oauth not meant for this client ({}), redirecting user to login again: {}",clientId, jsonObject);
            return redirectUserToOauthLoginUi();
        }

//        // TODO
//        // if (isTokenExpiredOrNearlySo(...) { ... }
        
        return true;
    }

    private boolean isEmailAuthorized(String email) {
        String domain="";
        if(Strings.isNonBlank(email)){
            if(email.contains("@")){
                domain=email.substring(email.lastIndexOf("@") +1);
            }
        }
        return (authorizedDomains.contains(domain) || authorizedUsers.contains(email));
    }

    // TODO these http methods need tidying
    
    // makes a GET request to url and returns body as a string
    public String get(String url) throws ClientProtocolException, IOException {
        return execute(new HttpGet(url));
    }
    
    // makes a POST request to url with form parameters and returns body as a
    // string
    public String post(String url, Map<String, String> formParameters) throws ClientProtocolException, IOException {
        HttpPost request = new HttpPost(url);

        List<NameValuePair> nvps = new ArrayList<NameValuePair>();
        for (String key : formParameters.keySet()) {
            nvps.add(new BasicNameValuePair(key, formParameters.get(key)));
        }
        request.setEntity(new UrlEncodedFormEntity(nvps));

        return execute(request);
    }
    
    // makes request and checks response code for 200
    private String execute(HttpRequestBase request) throws ClientProtocolException, IOException {
        // TODO tidy
        HttpClient httpClient = new DefaultHttpClient();
        HttpResponse response = httpClient.execute(request);

        HttpEntity entity = response.getEntity();
        String body = EntityUtils.toString(entity);

        if (response.getStatusLine().getStatusCode() != 200) {
            throw new RuntimeException(
                    "Expected 200 but got " + response.getStatusLine().getStatusCode() + ", with body " + body);
        }

        return body;
    }

    private boolean redirectUserToOauthLoginUi() throws IOException, SecurityProviderDeniedAuthentication {
        String state=Identifiers.makeRandomId(12); //should be stored in session
        StringBuilder oauthUrl = new StringBuilder().append(uriAuthorize)
                .append("?response_type=").append("code")
                .append("&client_id=").append(clientId)
                .append("&redirect_uri=").append(callbackUri)
                .append("&scope=openid%20email")
                .append("&state=").append(state)
                .append("&access_type=offline")
                .append("&approval_prompt=force");

        throw new SecurityProviderDeniedAuthentication(
            Response.status(Status.FOUND).header(HttpHeader.LOCATION.asString(), oauthUrl.toString()).build());
    }

    private Request getJettyRequest() {
        return Optional.ofNullable(HttpConnection.getCurrentConnection())
                .map(HttpConnection::getHttpChannel)
                .map(HttpChannel::getRequest)
                .orElse(null);
    }

}
