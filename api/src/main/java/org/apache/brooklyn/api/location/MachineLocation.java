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
package org.apache.brooklyn.api.location;

import java.net.InetAddress;
import java.util.List;
import java.util.Map;

import org.apache.brooklyn.util.net.HasNetworkAddresses;

/**
 * A location that is a machine.
 *
 * This interface marks a {@link Location} being a network node with an IP address, 
 * and supports appropriate operations on the node.
 */
public interface MachineLocation extends AddressableLocation, HasNetworkAddresses {
    /**
     * @return the machine's network address.
     */
    @Override
    InetAddress getAddress();

    /** @deprecated since 0.7.0. Use getMachineDetails().getOsDetails() instead. */
    @Deprecated
    OsDetails getOsDetails();

    /*
     * @return hardware and operating system-specific details for the machine.
     */
    MachineDetails getMachineDetails();

    String getUser();

    int execCommands(String summaryForLogging, List<String> commands);

    int execCommands(Map<String, ?> props, String summaryForLogging, List<String> commands);

    int execCommands(String summaryForLogging, List<String> commands, Map<String, ?> env);

    int execCommands(Map<String, ?> props, String summaryForLogging, List<String> commands, Map<String, ?> env);

    int execScript(String summaryForLogging, List<String> commands);

    int execScript(Map<String, ?> props, String summaryForLogging, List<String> commands);

    int execScript(String summaryForLogging, List<String> commands, Map<String, ?> env);

    int execScript(Map<String, ?> props, String summaryForLogging, List<String> commands, Map<String, ?> env);
}
