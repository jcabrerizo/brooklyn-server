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

import java.util.Arrays;
import java.util.Collection;
import java.util.EnumSet;

import javax.servlet.DispatcherType;
import javax.servlet.Filter;

import org.apache.brooklyn.rest.apidoc.RestApiResourceScanner;
import org.apache.brooklyn.rest.filter.MyOauthFilter;
import org.apache.cxf.BusFactory;
import org.apache.cxf.jaxrs.servlet.CXFNonSpringJaxrsServlet;
import org.apache.cxf.transport.common.gzip.GZIPInInterceptor;
import org.apache.cxf.transport.common.gzip.GZIPOutInterceptor;
import org.eclipse.jetty.servlet.FilterHolder;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;

import io.swagger.config.ScannerFactory;
import org.eclipse.jetty.webapp.WebAppContext;

public class RestApiSetup {

    public static void installRest(ServletContextHandler context, Object... providers) {
        initSwagger();

        BrooklynRestApp app = new BrooklynRestApp();
        for (Object o : providers) {
            app.singleton(o);
        }

        CXFNonSpringJaxrsServlet servlet = new CXFNonSpringJaxrsServlet(app);
        servlet.setBus(BusFactory.newInstance().createBus());
        servlet.getBus().getInInterceptors().add(new GZIPInInterceptor());
        servlet.getBus().getInFaultInterceptors().add(new GZIPInInterceptor());
        servlet.getBus().getOutInterceptors().add(new GZIPOutInterceptor());
        final ServletHolder servletHolder = new ServletHolder(servlet);

        context.addServlet(servletHolder, "/v1/*");
    }

    @SafeVarargs
    public static void installServletFilters(ServletContextHandler context, Class<? extends Filter>... filters) {
        installServletFilters(context, Arrays.asList(filters));
    }

    public static void installServletFilters(ServletContextHandler context, Collection<Class<? extends Filter>> filters) {
        for (Class<? extends Filter> filter : filters) {
            context.addFilter(filter, "/*", EnumSet.allOf(DispatcherType.class));
        }
    }

    public static void initSwagger() {
        ScannerFactory.setScanner(new RestApiResourceScanner());
    }

    public static void installOauthServletFilters(WebAppContext context, Class<MyOauthFilter> myOauthFilterClass) {
        FilterHolder fh= context.addFilter(myOauthFilterClass, "/*", EnumSet.allOf(DispatcherType.class));
        setFilterParams(fh);
    }
    private static void setFilterParams(FilterHolder fh) {
        fh.setInitParameter(MyOauthFilter.PARAM_URI_GETTOKEN, "https://accounts.google.com/o/oauth2/token");
        fh.setInitParameter(MyOauthFilter.PARAM_URI_TOKEN_INFO, "https://www.googleapis.com/oauth2/v1/tokeninfo");
        fh.setInitParameter(MyOauthFilter.PARAM_URI_LOGIN_REDIRECT, "/login");
        fh.setInitParameter(MyOauthFilter.PARAM_CLIENT_ID,
                "789182012565-burd24h3bc0im74g2qemi7lnihvfqd02.apps.googleusercontent.com");
        fh.setInitParameter(MyOauthFilter.PARAM_CLIENT_SECRET, "X00v-LfU34U4SfsHqPKMWfQl");
        fh.setInitParameter(MyOauthFilter.PARAM_CALLBACK_URI, "http://localhost.io:8080/service/ping");
        fh.setInitParameter(MyOauthFilter.PARAM_AUDIENCE, "audience");
    }
}
