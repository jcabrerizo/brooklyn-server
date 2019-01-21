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
package org.apache.brooklyn.rest.util;

import org.apache.brooklyn.api.mgmt.ManagementContext;
import org.apache.brooklyn.rest.filter.BrooklynSecurityProviderFilterHelper;
import org.apache.brooklyn.util.collections.MutableSet;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.session.SessionHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.util.Set;

public class CrossBundleSessionSharer {
    private static final Logger log = LoggerFactory.getLogger(BrooklynSecurityProviderFilterHelper.class);

    public static Set<SessionHandler> SESSION_MANAGER_CACHE = MutableSet.of();

    /* check all contexts for sessions; surprisingly hard to configure session management for karaf/pax web container.
     * they _really_ want each servlet to have their own sessions. how you're meant to do oauth for multiple servlets i don't know! */
    public static HttpSession getSession(HttpServletRequest webRequest, ManagementContext mgmt, boolean create) {
        String requestedSessionId = webRequest.getRequestedSessionId();

        log.trace("SESSION for {}, wants session {}", webRequest.getRequestURI(), requestedSessionId);

        if (webRequest instanceof Request) {
            SessionHandler sm = ((Request)webRequest).getSessionHandler();
            boolean added = SESSION_MANAGER_CACHE.add( sm );
            log.trace("SESSION MANAGER found for {}: {} (added={})", webRequest.getRequestURI(), sm, added);
        } else {
            log.trace("SESSION MANAGER NOT found for {}: {}", webRequest.getRequestURI(), webRequest);
        }

        if (requestedSessionId!=null) {
            for (SessionHandler m: SESSION_MANAGER_CACHE) {
                HttpSession s = m.getHttpSession(requestedSessionId);
                if (s!=null) {
                    log.trace("SESSION found for {}: {} (valid={})", webRequest.getRequestURI(), s, m.isValid(s));
                    return s;
                }
            }
        }

        if (create) {
            HttpSession session = webRequest.getSession(true);
            log.trace("SESSION creating for {}: {}", webRequest.getRequestURI(), session);
            return session;
        }

        return null;  // not found
    }

    public static void failIfMultipleSessions(HttpServletRequest request, ManagementContext mgmt) {
        HttpSession s1 = request.getSession(false);
        HttpSession s2 = getSession(request, mgmt, false);
        if (s1!=null && s2!=null && !s1.equals(s2)) {
            // unfortunate that we have to do this as it means we can't call req.getSession(true) anywhere,
            // but the alternative is to do some messy bookkeeping to track all equivalent sessions
            // (or when user logs out we only log them out of one of their sessions!)
            // or find out how to modify the session handlers to share sessions across bundles.
            throw new IllegalStateException("Inconsistent sessions for request: "+request+" - "+request.getRequestURI());
        }
    }
}
