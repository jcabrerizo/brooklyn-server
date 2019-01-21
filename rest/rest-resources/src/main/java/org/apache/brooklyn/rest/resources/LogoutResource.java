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
package org.apache.brooklyn.rest.resources;

import java.net.URI;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import javax.ws.rs.core.UriInfo;

import org.apache.brooklyn.core.mgmt.entitlement.Entitlements;
import org.apache.brooklyn.core.mgmt.entitlement.WebEntitlementContext;
import org.apache.brooklyn.rest.api.LogoutApi;
import org.apache.brooklyn.rest.filter.BrooklynSecurityProviderFilterHelper;
import org.apache.brooklyn.rest.util.CrossBundleSessionSharer;
import org.apache.brooklyn.rest.util.ManagementContextProvider;
import org.apache.brooklyn.util.exceptions.Exceptions;

public class LogoutResource extends AbstractBrooklynRestResource implements LogoutApi {
    
    @Context HttpServletRequest req;
    @Context UriInfo uri;

    @Override
    public Response logout() {
        WebEntitlementContext ctx = (WebEntitlementContext) Entitlements.getEntitlementContext();
        
        if (ctx==null) {
            return Response.status(Status.BAD_REQUEST)
                .entity("No user logged in")
                .build();            
        }
        
        URI dest = uri.getBaseUriBuilder().path(LogoutApi.class).path(LogoutApi.class, "logoutUser").build(ctx.user());

        // When execution gets here we don't know whether this is the first fetch of logout() or a subsequent one
        // with a re-authenticated user. The only way to tell is compare if user names changed. So redirect to an URL
        // which contains the user name.
        return Response.temporaryRedirect(dest).build();
    }

    @Override
    public Response unAuthorize() {
        return Response.status(Status.UNAUTHORIZED)
               // NB: 2019-01 no longer returns a realm (there might not be a realm; in this code we don't know)
               // method is now deprecated anyway
               .build();
    }

    @Override
    public Response logoutUser(String user) {
        WebEntitlementContext ctx = (WebEntitlementContext) Entitlements.getEntitlementContext();
        if (user.equals(ctx.user())) {
            doLogout();

            return Response.status(Status.OK)
                   // 2019-01 no longer returns unauthorized, returns OK to indicate user is successfully logged out
                   // also the realm  is removed (there might not be a realm; in this code we don't know)
                   .build();
        } else {
            return Response.temporaryRedirect(uri.getAbsolutePathBuilder().replacePath("/").build()).build();
        }
    }

    private void doLogout() {
        HttpSession s1 = CrossBundleSessionSharer.getSession(req, new ManagementContextProvider(req.getServletContext()).getManagementContext(), false);
        HttpSession s2 = req.getSession(false);
        try {


            if (s1!=null) s1.removeAttribute(BrooklynSecurityProviderFilterHelper.AUTHENTICATED_USER_SESSION_ATTRIBUTE);
            if (s2!=null) s2.removeAttribute(BrooklynSecurityProviderFilterHelper.AUTHENTICATED_USER_SESSION_ATTRIBUTE);
            req.logout();
        } catch (ServletException e) {
            Exceptions.propagate(e);
        }
        if (s1!=null) s1.invalidate();
        if (s2!=null) s2.invalidate();
    }

}
