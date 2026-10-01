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

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

import org.jspecify.annotations.NonNull;

/**
 * A {@link FederationServiceStateStore} that keeps the state in the memory of one node.
 *
 * @author Martin Lindström
 */
public class InMemoryFederationServiceStateStore implements FederationServiceStateStore {

  /** The states, keyed by kind of service and identity. */
  private final Map<String, FederationServiceState> states = new ConcurrentHashMap<>();

  /** {@inheritDoc} */
  @Override
  public void record(final @NonNull FederationCallEvent event) {
    Objects.requireNonNull(event, "event must not be null");
    this.states.compute(event.getServiceType() + "|" + event.getServiceId(),
        (key, previous) -> FederationServiceState.after(previous, event));
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull List<FederationServiceState> getStates() {
    return this.states.values().stream()
        .sorted(Comparator.comparing(FederationServiceState::type).thenComparing(FederationServiceState::id))
        .toList();
  }

}
