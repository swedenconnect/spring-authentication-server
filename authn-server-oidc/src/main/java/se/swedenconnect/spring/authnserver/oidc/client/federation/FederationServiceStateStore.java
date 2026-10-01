/*
 * Copyright 2026 Sweden Connect
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package se.swedenconnect.spring.authnserver.oidc.client.federation;

import java.util.List;

import org.jspecify.annotations.NonNull;

/**
 * Where the {@link FederationServiceMonitor} keeps the state of the federation services. The library ships an
 * {@link InMemoryFederationServiceStateStore} and a {@link RedisFederationServiceStateStore}, where the nodes of a
 * deployment share the state so that every node reports the same.
 *
 * @author Martin Lindström
 */
public interface FederationServiceStateStore {

  /**
   * Records a call.
   *
   * @param event the call
   */
  void record(final @NonNull FederationCallEvent event);

  /**
   * Gets the state of every service that has been called.
   *
   * @return the states
   */
  @NonNull List<FederationServiceState> getStates();

}
