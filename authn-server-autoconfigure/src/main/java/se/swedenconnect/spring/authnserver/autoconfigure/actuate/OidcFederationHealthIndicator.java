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
package se.swedenconnect.spring.authnserver.autoconfigure.actuate;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.springframework.boot.health.contributor.AbstractHealthIndicator;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.Status;

import se.swedenconnect.spring.authnserver.oidc.client.federation.FederationServiceMonitor;
import se.swedenconnect.spring.authnserver.oidc.client.federation.FederationServiceState;

/**
 * Health of the federation services that the OpenID Provider calls: the resolver and every trust mark issuer.
 * <p>
 * The health comes from the calls the server makes, never from calls made by the health check. Each service reports
 * its latest outcome, its most recent failure and the number of failed calls since the latest successful one, so that
 * a failure is not hidden by a later success. A service whose latest call failed gives
 * {@link AuthnServerHealthStatus#WARNING}.
 * </p>
 *
 * @author Martin Lindström
 */
public class OidcFederationHealthIndicator extends AbstractHealthIndicator {

  /** The monitor of the federation services. */
  private final FederationServiceMonitor monitor;

  /**
   * Constructor.
   *
   * @param monitor the monitor of the federation services
   */
  public OidcFederationHealthIndicator(final @NonNull FederationServiceMonitor monitor) {
    super("Federation health check failed");
    this.monitor = Objects.requireNonNull(monitor, "monitor must not be null");
  }

  /** {@inheritDoc} */
  @Override
  protected void doHealthCheck(final Health.@NonNull Builder builder) {
    final List<Map<String, Object>> services = new ArrayList<>();
    boolean warning = false;
    for (final FederationServiceState state : this.monitor.getStates()) {
      final Map<String, Object> s = new LinkedHashMap<>();
      s.put("type", name(state.type()));
      s.put("id", state.id());
      s.put("latest-outcome", name(state.latestOutcome()));
      s.put("latest-call", state.latestCall().toString());
      s.put("failures-since-success", state.failuresSinceSuccess());
      if (state.lastFailure() != null) {
        final Map<String, Object> failure = new LinkedHashMap<>();
        failure.put("time", state.lastFailure().toString());
        if (state.lastFailureOutcome() != null) {
          failure.put("kind", name(state.lastFailureOutcome()));
        }
        if (state.lastFailureError() != null) {
          failure.put("error", state.lastFailureError());
        }
        s.put("last-failure", failure);
      }
      warning |= state.isFailing();
      services.add(s);
    }
    builder.withDetail("services", services);
    builder.status(warning ? AuthnServerHealthStatus.WARNING : Status.UP);
  }

  /**
   * Gets the name of an enum constant as it is shown.
   *
   * @param value the constant
   * @return the name
   */
  private static @NonNull String name(final @NonNull Enum<?> value) {
    return value.name().toLowerCase(Locale.ROOT).replace('_', '-');
  }

}
