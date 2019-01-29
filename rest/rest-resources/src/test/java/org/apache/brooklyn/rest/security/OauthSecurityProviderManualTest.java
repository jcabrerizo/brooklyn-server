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

import org.apache.brooklyn.api.mgmt.ManagementContext;
import org.apache.brooklyn.core.internal.BrooklynProperties;
import org.apache.brooklyn.core.test.entity.LocalManagementContextForTests;
import org.apache.brooklyn.rest.BrooklynOauthSecurityConfig;
import org.apache.brooklyn.rest.security.provider.OauthSecurityProvider;
import org.apache.brooklyn.rest.security.provider.SecurityProvider;

import javax.ws.rs.core.Response;
import java.io.IOException;
import java.util.Scanner;

public class OauthSecurityProviderManualTest {

    public static void main(String [] args) throws IOException {
        OauthSecurityProvider provider = new OauthSecurityProvider(generateMgmt());
        Scanner reader = new Scanner(System.in);
        try{
            provider.authenticate(null, null, null);
        }catch (SecurityProvider.SecurityProviderDeniedAuthentication e){
            Response r = e.getResponse();
            String url= r.getLocation().toString();
            System.out.println("Please go to "+ url +" get the code and paste here:");
            String code = reader.nextLine();
            String token = provider.requestTokenWithCode(code);
            System.out.println("Token: "+token);
            String tokenInfo = provider.httpGet(provider.getUriTokenInfo(), token);
            System.out.println("Token info: "+tokenInfo);
        }
    }

    private static ManagementContext generateMgmt() {
        ManagementContext mgmt = LocalManagementContextForTests.newInstance(buildProperties());
        return mgmt;
    }

    public static BrooklynProperties buildProperties() {
        BrooklynProperties props =BrooklynProperties.Factory.newEmpty();
        props.put(BrooklynOauthSecurityConfig.SECURITY_OAUTH_TOKEN_URL, "https://accounts.google.com/o/oauth2/token");
        props.put(BrooklynOauthSecurityConfig.SECURITY_OAUTH_AUTHENTICATE_URL, "https://accounts.google.com/o/oauth2/auth");
        props.put(BrooklynOauthSecurityConfig.SECURITY_OAUTH_VALIDATE_URL, "https://www.googleapis.com/oauth2/v2/userinfo");
        props.put(BrooklynOauthSecurityConfig.SECURITY_OAUTH_CLIENT_ID, "789182012565-burd24h3bc0im74g2qemi7lnihvfqd02.apps.googleusercontent.com");
        props.put(BrooklynOauthSecurityConfig.SECURITY_OAUTH_CLIENT_SECRET, "X00v-LfU34U4SfsHqPKMWfQl");
        props.put(BrooklynOauthSecurityConfig.SECURITY_OAUTH_CALLBACK, "http://localhost.io:8081/");
        props.put(BrooklynOauthSecurityConfig.SECURITY_OAUTH_AUTHORIZED_USERS, "");
        props.put(BrooklynOauthSecurityConfig.SECURITY_OAUTH_AUTHORIZED_DOMAINS, "cloudsoftcorp.com");
        props.put(BrooklynOauthSecurityConfig.SECURITY_OAUTH_AUDIENCE, "audience");
        props.put(BrooklynOauthSecurityConfig.SECURITY_OAUTH_TOKEN_RESPONSE_KEY, "access_token");
        props.put(BrooklynOauthSecurityConfig.SECURITY_OAUTH_CODE_INPUT_PARAMETER_NAME, "code");
        props.put(BrooklynOauthSecurityConfig.SECURITY_OAUTH_CODE_OUTPUT_PARAMETER_NAME, "code");
        props.put(BrooklynOauthSecurityConfig.SECURITY_OAUTH_SCOPE, "https://www.googleapis.com/auth/userinfo.email+https://www.googleapis.com/auth/userinfo.profile");

//        props.put(BrooklynWebConfig.SECURITY_PROVIDER_INSTANCE, new OauthSecurityProvider(getManagementContext()));

        return props;
    }
}
