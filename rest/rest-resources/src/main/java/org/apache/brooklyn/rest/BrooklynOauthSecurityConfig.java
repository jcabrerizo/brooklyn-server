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
package org.apache.brooklyn.rest;

import org.apache.brooklyn.config.ConfigKey;
import org.apache.brooklyn.core.config.ConfigKeys;

public class BrooklynOauthSecurityConfig {
    public final static String BASE_NAME_OAUTH = BrooklynWebConfig.BASE_NAME_SECURITY+".oauth";

    public final static ConfigKey<String> SECURITY_OAUTH_TOKEN_URL = ConfigKeys.newStringConfigKey(
            BASE_NAME_OAUTH+".tokenUrl", "URL to get the user token");

    public final static ConfigKey<String> SECURITY_OAUTH_AUTHENTICATE_URL = ConfigKeys.newStringConfigKey(
            BASE_NAME_OAUTH+".authenticateUrl", "URL to authorize the user");

    public final static ConfigKey<String> SECURITY_OAUTH_VALIDATE_URL = ConfigKeys.newStringConfigKey(
            BASE_NAME_OAUTH+".validateUrl", "URL to validate the token");

    public final static ConfigKey<String> SECURITY_OAUTH_CLIENT_ID = ConfigKeys.newStringConfigKey(
            BASE_NAME_OAUTH+".clientId", "Client ID registered in the authentication server");

    public final static ConfigKey<String> SECURITY_OAUTH_CLIENT_SECRET= ConfigKeys.newStringConfigKey(
            BASE_NAME_OAUTH+".clientSecret", "Client Secret to validate the token");

    public final static ConfigKey<String> SECURITY_OAUTH_CALLBACK= ConfigKeys.newStringConfigKey(
            BASE_NAME_OAUTH+".callback", "Callback URL after authentication");

    public final static ConfigKey<String> SECURITY_OAUTH_AUTHORIZED_USERS= ConfigKeys.newStringConfigKey(
            BASE_NAME_OAUTH+".users", "Comma separated list of users authorized");

    public final static ConfigKey<String> SECURITY_OAUTH_AUTHORIZED_DOMAINS= ConfigKeys.newStringConfigKey(
            BASE_NAME_OAUTH+".domains", "Comma separated list of domains authorized");

    public final static ConfigKey<String> SECURITY_OAUTH_AUDIENCE= ConfigKeys.newStringConfigKey(
            BASE_NAME_OAUTH+".audience", "Oauth audience", "audience");

    public final static ConfigKey<String> SECURITY_OAUTH_TOKEN_RESPONSE_KEY= ConfigKeys.newStringConfigKey(
            BASE_NAME_OAUTH+".tokenResponseKey", "Key name of the token in the servers response", "access_token");

    public final static ConfigKey<String> SECURITY_OAUTH_CODE_INPUT_PARAMETER_NAME= ConfigKeys.newStringConfigKey(
            BASE_NAME_OAUTH+".codeInputParameterName", "Name of the parameter to get the code from the redirection", "code");

    public final static ConfigKey<String> SECURITY_OAUTH_CODE_OUTPUT_PARAMETER_NAME= ConfigKeys.newStringConfigKey(
            BASE_NAME_OAUTH+".codeOutputParameterName", "Name of the parameter to sent the request for authenticate", "code");

    public final static ConfigKey<String> SECURITY_OAUTH_SCOPE= ConfigKeys.newStringConfigKey(
            BASE_NAME_OAUTH+".scope", "Oauth scope requested");
}
