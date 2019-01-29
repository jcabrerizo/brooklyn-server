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

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableMap;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.apache.brooklyn.api.mgmt.ManagementContext;
import org.apache.brooklyn.rest.filter.BrooklynSecurityProviderFilterHelper;
import org.apache.brooklyn.util.exceptions.Exceptions;
import org.apache.brooklyn.util.http.HttpTool;
import org.apache.brooklyn.util.http.HttpToolResponse;
import org.apache.brooklyn.util.net.Urls;
import org.apache.brooklyn.util.text.Identifiers;
import org.apache.brooklyn.util.text.Strings;
import org.apache.brooklyn.util.yaml.Yamls;
import org.apache.http.client.ClientProtocolException;
import org.eclipse.jetty.http.HttpHeader;
import org.eclipse.jetty.server.HttpChannel;
import org.eclipse.jetty.server.HttpConnection;
import org.eclipse.jetty.server.Request;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.annotations.Beta;

import static org.apache.brooklyn.rest.BrooklynOauthSecurityConfig.*;

/** Configurable OAuth redirect security provider
 * 
 *  Redirects all inbound requests to an oauth web server unless a session token is specified. */
@Beta  // work in progress
public class OauthSecurityProvider implements SecurityProvider {

    public static final Logger log = LoggerFactory.getLogger(OauthSecurityProvider.class);
    private final Gson gson;
    public static final String CHARSET_NAME = "UTF-8";
    public static final ImmutableMap<String, String> MINIMAL_HEADERS = ImmutableMap.of(
            "Content-Type", "application/json; charset=" + CHARSET_NAME,
            "Accept", "application/json",
            "Accept-Charset", CHARSET_NAME);
    private static final String OAUTH_ACCESS_TOKEN_SESSION_KEY = "org.apache.brooklyn.security.oauth.access_token";
    private static final String OAUTH_ACCESS_TOKEN_EXPIRY_UTC_KEY = "org.apache.brooklyn.security.oauth.access_token_expiry_utc";

    // tempting to use getJettyRequest().getRequestURL().toString();
    // but some oauth providers require this to be declared
    private String callbackUri;
    private String accessTokenResponseKey;
    private String audience;
    private String codeInputParameter = "code";
    private String codeOutputParameter = "code";

    // google test data - hard-coded for now
    private String uriGetToken;
    private String uriAuthenticate;
    private String uriTokenInfo;
    @VisibleForTesting
    public String getUriTokenInfo() {
        return uriTokenInfo;
    }

    private String clientId;
    private String clientSecret;
    private String scope;

    // Authorized users and domains
    private Set<String> authorizedUsers;
    private Set<String> authorizedDomains;
    
    protected final ManagementContext mgmt;

    public OauthSecurityProvider(ManagementContext mgmt) {
        this.mgmt = mgmt;
        initialize();
        gson = new GsonBuilder().create();
    }

    private synchronized void initialize() {
        uriGetToken = mgmt.getConfig().getConfig(SECURITY_OAUTH_TOKEN_URL);
        Preconditions.checkNotNull(uriGetToken, "URI to get token must be set: "+SECURITY_OAUTH_TOKEN_URL.getName());

        uriAuthenticate = mgmt.getConfig().getConfig(SECURITY_OAUTH_AUTHENTICATE_URL);
        Preconditions.checkNotNull(uriAuthenticate, "URI to authorize must be set: "+ SECURITY_OAUTH_AUTHENTICATE_URL.getName());

        uriTokenInfo = mgmt.getConfig().getConfig(SECURITY_OAUTH_VALIDATE_URL);
        Preconditions.checkNotNull(uriTokenInfo, "URI to validate the current token must be set: "+SECURITY_OAUTH_VALIDATE_URL.getName());

        clientId = mgmt.getConfig().getConfig(SECURITY_OAUTH_CLIENT_ID);
        Preconditions.checkNotNull(clientId, "Client ID must be set: "+SECURITY_OAUTH_CLIENT_ID.getName());

        clientSecret = mgmt.getConfig().getConfig(SECURITY_OAUTH_CLIENT_SECRET);
        Preconditions.checkNotNull(clientSecret, "Client secret must be set: "+SECURITY_OAUTH_CLIENT_SECRET.getName());

        callbackUri = mgmt.getConfig().getConfig(SECURITY_OAUTH_CALLBACK);
        Preconditions.checkNotNull(callbackUri, "Callback URL must be set: "+SECURITY_OAUTH_CALLBACK.getName());

        scope = mgmt.getConfig().getConfig(SECURITY_OAUTH_SCOPE);
        Preconditions.checkNotNull(scope, "Token request scope must be set: "+SECURITY_OAUTH_SCOPE.getName());

        audience = mgmt.getConfig().getConfig(SECURITY_OAUTH_AUDIENCE);
        accessTokenResponseKey = mgmt.getConfig().getConfig(SECURITY_OAUTH_TOKEN_RESPONSE_KEY);
        codeInputParameter= mgmt.getConfig().getConfig(SECURITY_OAUTH_CODE_INPUT_PARAMETER_NAME);
        codeOutputParameter= mgmt.getConfig().getConfig(SECURITY_OAUTH_CODE_OUTPUT_PARAMETER_NAME);

        String authorizedUsersReaded= mgmt.getConfig().getConfig(SECURITY_OAUTH_AUTHORIZED_USERS);
        if(Strings.isNonBlank(authorizedUsersReaded)){
            authorizedUsers = new HashSet<>(Arrays.asList(authorizedUsersReaded.split("\\s*,\\s*")));
        }else{
            authorizedUsers= Collections.EMPTY_SET;
        }

        String authorizedDomainsReaded= mgmt.getConfig().getConfig(SECURITY_OAUTH_AUTHORIZED_DOMAINS);
        if(Strings.isNonBlank(authorizedDomainsReaded)){
            authorizedDomains = new HashSet<>(Arrays.asList(authorizedDomainsReaded.split("\\s*,\\s*")));
        }else{
            authorizedDomains= Collections.EMPTY_SET;
        }
    }
    
    @Override
    public boolean isAuthenticated(HttpSession session) {
        // TODO tidy log messages
        log.trace("OauthSecurityProvider.isAuthenticated. RequestURI: {} | Session: {} ",getJettyRequest()==null?"null":getJettyRequest().getRequestURI(),session);
        if(session==null || // no session
                Strings.isNonBlank(getCodeFromRequest()) || // arriving just after login on server
                Strings.isBlank((String) session.getAttribute(OAUTH_ACCESS_TOKEN_SESSION_KEY)) // not having a saved token
        ){ return false;}

        try {
            return validateTokenAgainstOauthServer((String) session.getAttribute(OAUTH_ACCESS_TOKEN_SESSION_KEY),session);
        } catch (Exception e) {
            return  false;
        }
    }

    @Override
    public boolean authenticate(HttpSession session, String user, String password) throws SecurityProviderDeniedAuthentication {
        log.trace("OauthSecurityProvider.authenticate. Session: {} | User: ",session, user);
        
        if (isAuthenticated(session)) {
            return true;
        }

        // Redirection from the authenticator server
        String code = getCodeFromRequest();
        // Getting token, if exists, from the current session
        String token = getTokenFromSession(session);
        
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
            log.warn("OauthSecurityProvider.authenticate Error performing OAuth: "+e, e);
            throw Exceptions.propagate(e);
        }
    }

    private String getTokenFromSession(HttpSession session) {
        if(session==null){
            return  null;
        }
        return (String) session.getAttribute(OAUTH_ACCESS_TOKEN_SESSION_KEY);
    }

    private String getCodeFromRequest() {
        Request request= getJettyRequest();
        if(request==null){
            return null;
        }
        return request.getParameter(codeInputParameter);
    }

    @Override
    public boolean logout(HttpSession session) {
        log.trace("OauthSecurityProvider.logout");
        session.removeAttribute(OAUTH_ACCESS_TOKEN_SESSION_KEY);
        session.removeAttribute(OAUTH_ACCESS_TOKEN_EXPIRY_UTC_KEY);
        return true;
    }
    
    @Override
    public boolean requiresUserPass() {
        return false;
    }

    private boolean retrieveTokenForAuthCodeFromOauthServer(HttpSession session, String code) throws ClientProtocolException, IOException, ServletException, SecurityProviderDeniedAuthentication {
        // get the access token from json and request info from Google
        String accessToken=Strings.EMPTY;
        try {
            accessToken =  requestTokenWithCode(code);
        } catch (Exception e) {
            Exceptions.propagateIfFatal(e);
            log.trace("OauthSecurityProvider.retrieveTokenForAuthCodeFromOauthServer");
            return redirectUserToOauthLoginUi();
        }

        // Put token in session
        if(validateTokenAgainstOauthServer(accessToken,session)){
            session.setAttribute(OAUTH_ACCESS_TOKEN_SESSION_KEY, accessToken);
            return true;
        }
        return false; // not validated
    }

    @VisibleForTesting
    public String requestTokenWithCode(String code) throws IOException {
        // get the access token by post to Google
        HashMap<String, String> params = new HashMap<String, String>();
        params.put(codeOutputParameter, code);
        params.put("client_id", clientId);
        params.put("client_secret", clientSecret);
        params.put("redirect_uri", callbackUri);
        params.put("grant_type", "authorization_code");

        String body = httpPost(uriGetToken, params);
        final Map<?, ?> jsonObject = string2map(body);
        log.trace("OauthSecurityProvider.retrieveTokenForAuthCodeFromOauthServer Parsed '"+body+"' as "+jsonObject);
        return (String) jsonObject.get(accessTokenResponseKey);
    }

    private boolean validateTokenAgainstOauthServer(String token, HttpSession session) throws IOException,SecurityProviderDeniedAuthentication {
        // TODO support validation, and run periodically

        String body = httpGet(uriTokenInfo, token);

        Map<?,?> jsonObject = null;
        // get the access token from json and request info from Google
        String user="";
        String email="";
        try {
            jsonObject = string2map(body);
            @SuppressWarnings("unchecked")
            Map<String,String> info = Yamls.getAs( Yamls.parseAll(body), Map.class );
            email = info.get("email");
            if(!isEmailAuthorized(email)){
                throw new SecurityProviderDeniedAuthentication(Response.status(Status.UNAUTHORIZED).entity("Authorization failed").build());
            }
            user = info.get("name");
            if(Strings.isBlank(user)){
                user=email;
            }
            session.setAttribute(BrooklynSecurityProviderFilterHelper.AUTHENTICATED_USER_SESSION_ATTRIBUTE, user);
            log.trace("OauthSecurityProvider.retrieveTokenForAuthCodeFromOauthServer Parsed '{}' as {}", body ,jsonObject);
        }catch(SecurityProviderDeniedAuthentication e){
            log.trace("OauthSecurityProvider.retrieveTokenForAuthCodeFromOauthServer User not authorized '{}'",user);
            throw e;
        }
        catch (Exception e) {
            Exceptions.propagateIfFatal(e);
            log.trace("OauthSecurityProvider.retrieveTokenForAuthCodeFromOauthServer Unable to parse: '{}'",body);
            throw new RuntimeException("Unable to parse json " + body, e);
        }

//        TODO
//        if (isTokenExpiredOrNearlySo(...) { ... }
        
        return true;
    }

    private Map<?, ?> string2map(String body) {
        return (Map<?, ?>) Yamls.parseAll(body).iterator().next();
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

    // makes a GET request to url and returns body as a string
    @VisibleForTesting
    public String httpGet(String url, String token) throws ClientProtocolException, IOException {
        Map<String, String> headers = ImmutableMap.<String, String>builder().put("Authorization", "Bearer "+token)
                .build();
        HttpToolResponse response = HttpTool.httpGet(HttpTool.httpClientBuilder().build(), Urls.toUri(url), headers);
        return new String(response.getContent(),CHARSET_NAME);
    }
    
    // makes a POST request to url with form parameters and returns body as a
    // string
    @VisibleForTesting
    public String httpPost(String url, Map<String, String> formParameters) throws ClientProtocolException, IOException {
        String body = gson.toJson(formParameters);
        HttpToolResponse response = HttpTool.httpPost(HttpTool.httpClientBuilder().build(),
                Urls.toUri(url),
                MINIMAL_HEADERS,
                body.getBytes());
        return new String(response.getContent(),CHARSET_NAME);
    }

    private boolean redirectUserToOauthLoginUi() throws IOException, SecurityProviderDeniedAuthentication {
        String state=Identifiers.makeRandomId(12); //should be stored in session
        StringBuilder oauthUrl = new StringBuilder().append(uriAuthenticate)
                .append("?response_type=").append(codeInputParameter)
                .append("&client_id=").append(clientId)
                .append("&redirect_uri=").append(callbackUri)
                .append("&scope=").append(scope)
                .append("&state=").append(state)
                .append("&access_type=offline")
                .append("&approval_prompt=force");

        throw new SecurityProviderDeniedAuthentication(
            //No cached redirection
            Response.status(Status.FOUND).header(HttpHeader.LOCATION.asString(), oauthUrl.toString())
                    .header(HttpHeader.EXPIRES.toString(),"0")
                    .header(HttpHeader.CACHE_CONTROL.toString(), "no-cache, no-store")
                    .header(HttpHeader.PRAGMA.toString(), "no-cache")
                    .build());
    }

    private Request getJettyRequest() {
        return Optional.ofNullable(HttpConnection.getCurrentConnection())
                .map(HttpConnection::getHttpChannel)
                .map(HttpChannel::getRequest)
                .orElse(null);
    }

}
