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
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.springframework.context.ApplicationListener;

/**
 * Keeps track of how the calls to each federation service go, from the {@link FederationCallEvent}s that the
 * {@link HttpFederationClient} publishes: the resolver, and every trust mark issuer that the server calls. It never
 * calls a service itself.
 *
 * @author Martin Lindström
 */
public class FederationServiceMonitor implements ApplicationListener<FederationCallEvent> {

  /** Where the state is kept. */
  private final FederationServiceStateStore store;

  /**
   * Constructor.
   *
   * @param store where the state is kept
   */
  public FederationServiceMonitor(final @NonNull FederationServiceStateStore store) {
    this.store = Objects.requireNonNull(store, "store must not be null");
  }

  /** {@inheritDoc} */
  @Override
  public void onApplicationEvent(final @NonNull FederationCallEvent event) {
    this.store.record(event);
  }

  /**
   * Gets the state of every service that has been called.
   *
   * @return the states
   */
  public @NonNull List<FederationServiceState> getStates() {
    return this.store.getStates();
  }

}
