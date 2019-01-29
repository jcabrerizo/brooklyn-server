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
package org.apache.brooklyn.rest.security;

import org.apache.brooklyn.core.internal.BrooklynProperties;
import org.apache.brooklyn.rest.BrooklynOauthSecurityConfig;
import org.apache.brooklyn.rest.BrooklynWebConfig;
import org.apache.brooklyn.rest.filter.*;
import org.apache.brooklyn.rest.security.provider.OauthSecurityProvider;
import org.apache.brooklyn.rest.testing.BrooklynRestResourceTest;
import org.apache.brooklyn.util.text.Strings;
import org.apache.cxf.jaxrs.JAXRSServerFactoryBean;
import org.apache.cxf.jaxrs.client.WebClient;
import org.eclipse.jetty.server.session.SessionHandler;
import org.testng.annotations.Test;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

    public class OauthSecurityProviderTest  extends BrooklynRestResourceTest {

        public static final String AUTHENTICATION_ENDPOINT = "https://accounts.google.com/o/oauth2/auth";

        public static class TestResource {
        @GET
        @Path("/test")
        public String test() {
            return "test";
        }
    }

    @Override
    protected void configureCXF(JAXRSServerFactoryBean sf) {
        BrooklynProperties props = (BrooklynProperties)getManagementContext().getConfig();
        props.put(BrooklynOauthSecurityConfig.SECURITY_OAUTH_TOKEN_URL, "https://accounts.google.com/o/oauth2/token");
        props.put(BrooklynOauthSecurityConfig.SECURITY_OAUTH_AUTHENTICATE_URL, AUTHENTICATION_ENDPOINT);
        props.put(BrooklynOauthSecurityConfig.SECURITY_OAUTH_VALIDATE_URL, "https://www.googleapis.com/oauth2/v2/userinfo");
        props.put(BrooklynOauthSecurityConfig.SECURITY_OAUTH_CLIENT_ID, "789182012565-burd24h3bc0im74g2qemi7lnihvfqd02.apps.googleusercontent.com");
        props.put(BrooklynOauthSecurityConfig.SECURITY_OAUTH_CLIENT_SECRET, "X00v-LfU34U4SfsHqPKMWfQl");
        props.put(BrooklynOauthSecurityConfig.SECURITY_OAUTH_CALLBACK, "http://localhost.io:9998/testPath");
        props.put(BrooklynOauthSecurityConfig.SECURITY_OAUTH_AUTHORIZED_USERS, "");
        props.put(BrooklynOauthSecurityConfig.SECURITY_OAUTH_AUTHORIZED_DOMAINS, "cloudsoftcorp.com");
        props.put(BrooklynOauthSecurityConfig.SECURITY_OAUTH_AUDIENCE, "audience");
        props.put(BrooklynOauthSecurityConfig.SECURITY_OAUTH_TOKEN_RESPONSE_KEY, "access_token");
        props.put(BrooklynOauthSecurityConfig.SECURITY_OAUTH_CODE_INPUT_PARAMETER_NAME, "code");
        props.put(BrooklynOauthSecurityConfig.SECURITY_OAUTH_CODE_OUTPUT_PARAMETER_NAME, "code");
        props.put(BrooklynOauthSecurityConfig.SECURITY_OAUTH_SCOPE, "https://www.googleapis.com/auth/userinfo.email+https://www.googleapis.com/auth/userinfo.profile");

        props.put(BrooklynWebConfig.SECURITY_PROVIDER_INSTANCE, new OauthSecurityProvider(getManagementContext()));

        sf.setProvider(new SessionHandler());
        super.configureCXF(sf);
    }

    @Override
    protected void addBrooklynResources() {
        addResource(new BrooklynSecurityProviderFilterJersey());
        addResource(new TestResource());
    }

    @Test
    public void testLoginRedirection() {
        Response response = fetch("/test");
        // test status
        assertEquals(response.getStatus(), Response.Status.TEMPORARY_REDIRECT.getStatusCode());
        // test authorise URL
        assertTrue(response.getMetadata().get("Location").get(0).toString().startsWith(AUTHENTICATION_ENDPOINT));
    }

    protected Response fetch(String path) {
        WebClient resource = WebClient.create(getEndpointAddress(), clientProviders, Strings.EMPTY, Strings.EMPTY, null)
                .path(path)
                .accept(MediaType.APPLICATION_JSON_TYPE);
        Response response = resource.get();
        return response;
    }
}

