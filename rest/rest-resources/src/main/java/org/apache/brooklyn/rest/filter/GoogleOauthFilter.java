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
package org.apache.brooklyn.rest.filter;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.annotation.Priority;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Request;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.Provider;

import net.minidev.json.JSONObject;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.entity.ContentType;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Provider
@Priority(1)
public class GoogleOauthFilter implements ContainerRequestFilter {
    private static final Logger log = LoggerFactory.getLogger(GoogleOauthFilter.class);
    public static final String SESSION_KEY_CODE = "code";

    public static final String SESSION_KEY_ACCESS_TOKEN = "access_token";

    public static final String PARAM_URI_TOKEN_INFO = "uriTokenInfo";
    public static final String PARAM_URI_GETTOKEN = "uriGetToken";
    public static final String PARAM_URI_LOGIN_REDIRECT = "uriLoginRedirect";
    public static final String PARAM_CLIENT_ID = "clientId";
    public static final String PARAM_CLIENT_SECRET = "clientSecret";
    public static final String PARAM_CALLBACK_URI = "callbackUri";
    public static final String PARAM_AUDIENCE = "audience";

    private String uriGetToken = "https://accounts.google.com/o/oauth2/token";
    private String uriTokenInfo = "https://www.googleapis.com/oauth2/v1/tokeninfo";
    private String uriTokenRedirect = "/";
    private String clientId = "789182012565-burd24h3bc0im74g2qemi7lnihvfqd02.apps.googleusercontent.com";
    private String clientSecret = "X00v-LfU34U4SfsHqPKMWfQl";
    private String callbackUri = "http://localhost.io:8081/";
    private String audience = "audience";

    @Context
    HttpServletRequest webRequest;

    private void initializateParams(FilterConfig filterConfig) {
        Enumeration<String> enums = filterConfig.getInitParameterNames();

        while (enums.hasMoreElements()) {
            String paramKey = enums.nextElement();
            String paramValue = filterConfig.getInitParameter(paramKey);
            System.out.println(paramKey + ":" + paramValue);
            switch (paramKey) {
            case PARAM_URI_TOKEN_INFO:
                uriTokenInfo = paramValue;
                break;
            case PARAM_URI_GETTOKEN:
                uriGetToken = paramValue;
                break;
            case PARAM_URI_LOGIN_REDIRECT:
                uriTokenRedirect = paramValue;
                break;
            case PARAM_CLIENT_ID:
                clientId = paramValue;
                break;
            case PARAM_CLIENT_SECRET:
                clientSecret = paramValue;
                break;
            case PARAM_CALLBACK_URI:
                callbackUri = paramValue;
                break;
            case PARAM_AUDIENCE:
                audience = paramValue;
                break;
            default:
                System.out.println("Ignored param: " + paramKey + ":" + paramValue);
            }
        }
    }

    private boolean validateToken(String token,ContainerRequestContext requestContext) throws ClientProtocolException, IOException {
        // System.out.println("########################### Validating token
        // ###########################");
        HashMap<String, String> params = new HashMap<String, String>();
        params.put(SESSION_KEY_ACCESS_TOKEN, token);

        String body = post(uriTokenInfo, params);
        // System.out.println(body);
        JSONObject jsonObject = null;

        // get the access token from json and request info from Google
//        try {
//            jsonObject = (JSONObject) new JSONParser().parse(body);
//        } catch (ParseException e) {
//            throw new RuntimeException("Unable to parse json " + body);
//        }

        if (!clientId.equals(jsonObject.get(audience))) {
            redirectLogin(requestContext);
        }
        // if (isTokenExpiredOrNearlySo(...) { ... }
        return true;
    }

    private boolean getToken(ServletRequest req)
            throws ClientProtocolException, IOException, ServletException {
        String code = req.getParameter(SESSION_KEY_CODE);

        // get the access token by post to Google
        HashMap<String, String> params = new HashMap<String, String>();
        params.put(SESSION_KEY_CODE, code);
        params.put("client_id", clientId);
        params.put("client_secret", clientSecret);
        params.put("redirect_uri", callbackUri);
        params.put("grant_type", "authorization_code");

        String body = post(uriGetToken, params);

        JSONObject jsonObject = null;

        // get the access token from json and request info from Google
//        try {
//            jsonObject = (JSONObject) new JSONParser().parse(body);
//        } catch (ParseException e) {
//            // throw new RuntimeException("Unable to parse json " + body);
//            return redirectLogin(resp);
//        }

        // Left token and code in session
        String accessToken = (String) jsonObject.get(SESSION_KEY_ACCESS_TOKEN);
        HttpServletRequest request = (HttpServletRequest) req;
        request.getSession().setAttribute(SESSION_KEY_ACCESS_TOKEN, accessToken);
        request.getSession().setAttribute(SESSION_KEY_CODE, code);

        // resp.getWriter().println(json);
        return true;
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

    // makes a GET request to url and returns body as a string
    public String get(String url) throws ClientProtocolException, IOException {
        return execute(new HttpGet(url));
    }

    // makes request and checks response code for 200
    private String execute(HttpRequestBase request) throws ClientProtocolException, IOException {
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

    private void redirectLogin(ContainerRequestContext requestContext)  {
//        HttpServletResponse res = (HttpServletResponse) response;
//        res.setContentType(ContentType.APPLICATION_XML.toString());
//        res.sendRedirect(uriTokenRedirect);
        String state="state";
        StringBuilder oauthUrl = new StringBuilder().append("https://accounts.google.com/o/oauth2/auth")
                .append("?client_id=").append(clientId) // the client id from the api console registration
                .append("&response_type=code").append("&scope=openid%20email") // scope is the api permissions we
                // are requesting
                .append("&redirect_uri=").append(callbackUri) // the servlet that google redirects to after
                // authorization
                .append("&state=").append(state)
                .append("&access_type=offline") // here we are asking to access to user's data while they are not
                // signed in
                .append("&approval_prompt=force"); // this requires them to verify which account to use, if they are
        // already signed in
        Response.ResponseBuilder builder = null;
        String response = "oAuth redirection";
        URI uri= null;
        try {
            uri = new URI(oauthUrl.toString());
        } catch (URISyntaxException e) {
           log.debug("URI error for: {}",oauthUrl);
        }

        requestContext.abortWith(Response.status(Response.Status.TEMPORARY_REDIRECT).location(uri).build());
//        builder = Response.status(Response.Status.ACCEPTED).location(uri).entity(response);
//        throw new WebApplicationException(builder.build());

    }



    @Override
    public void filter(ContainerRequestContext requestContext) throws IOException {
        log.debug(">>>>>>>>>>> filter");
        Request req = requestContext.getRequest();
//        HttpServletRequest request = (HttpServletRequest) req;
        // Redirection from the authenticator server
        String code = webRequest.getParameter(SESSION_KEY_CODE);

        // Getting token, if exists, from the current session
        String token = (String) webRequest.getSession().getAttribute(SESSION_KEY_ACCESS_TOKEN);

        if (code != null && !"".equals(code)) { // in brooklyn, have
            // Strings.isNonBlank(code)
            try {
                getToken(webRequest);
            } catch (ServletException e) {
                e.printStackTrace();
            }
        } else if (token == null || "".equals(token)) { // isBlank
            redirectLogin(requestContext);
        } else {
            validateToken(token,requestContext);
        }
//        if (continueFilterProcessing) {
//            chain.doFilter(req, resp);
//        }
    }
}
