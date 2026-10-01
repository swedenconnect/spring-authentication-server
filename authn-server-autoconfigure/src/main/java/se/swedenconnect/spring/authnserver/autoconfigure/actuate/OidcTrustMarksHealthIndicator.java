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
import java.util.Map;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.springframework.boot.health.contributor.AbstractHealthIndicator;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.Status;

import se.swedenconnect.spring.authnserver.oidc.federation.ProviderTrustMarks;
import se.swedenconnect.spring.authnserver.oidc.federation.TrustMarkState;

/**
 * Health of the OpenID Provider's own trust marks. A trust mark type whose latest fetch or renewal failed, or that has
 * no valid trust mark, gives {@link AuthnServerHealthStatus#WARNING}. The state is the one that
 * {@link ProviderTrustMarks} records, so with a shared store every node reports the same.
 *
 * @author Martin Lindström
 */
public class OidcTrustMarksHealthIndicator extends AbstractHealthIndicator {

  /** The trust marks of the OpenID Provider. */
  private final ProviderTrustMarks trustMarks;

  /**
   * Constructor.
   *
   * @param trustMarks the trust marks of the OpenID Provider
   */
  public OidcTrustMarksHealthIndicator(final @NonNull ProviderTrustMarks trustMarks) {
    super("Trust mark health check failed");
    this.trustMarks = Objects.requireNonNull(trustMarks, "trustMarks must not be null");
  }

  /** {@inheritDoc} */
  @Override
  protected void doHealthCheck(final Health.@NonNull Builder builder) {
    final List<Map<String, Object>> marks = new ArrayList<>();
    boolean warning = false;
    for (final TrustMarkState state : this.trustMarks.getStates()) {
      final Map<String, Object> m = new LinkedHashMap<>();
      m.put("type", state.trustMarkType());
      m.put("published", state.published());
      if (state.expiresAt() != null) {
        m.put("expires-at", state.expiresAt().toString());
      }
      if (state.lastFetched() != null) {
        m.put("last-fetched", state.lastFetched().toString());
      }
      if (state.isFailing()) {
        m.put("failures", state.consecutiveFailures());
        if (state.lastFailure() != null) {
          m.put("last-failure", state.lastFailure().toString());
        }
        if (state.lastFailureReason() != null) {
          m.put("error", state.lastFailureReason());
        }
      }
      if (state.isFailing() || !state.published()) {
        warning = true;
      }
      marks.add(m);
    }
    builder.withDetail("trust-marks", marks);
    builder.status(warning ? AuthnServerHealthStatus.WARNING : Status.UP);
  }

}
