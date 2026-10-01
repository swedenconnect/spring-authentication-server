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

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.Status;
import org.springframework.core.env.StandardEnvironment;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;

import se.swedenconnect.spring.authnserver.oidc.client.federation.FederationCallEvent;
import se.swedenconnect.spring.authnserver.oidc.client.federation.FederationServiceMonitor;
import se.swedenconnect.spring.authnserver.oidc.client.federation.HttpFederationClient;
import se.swedenconnect.spring.authnserver.oidc.client.federation.InMemoryFederationServiceStateStore;
import se.swedenconnect.spring.authnserver.oidc.federation.InMemoryProviderTrustMarkStore;
import se.swedenconnect.spring.authnserver.oidc.federation.ProviderTrustMarkStore;
import se.swedenconnect.spring.authnserver.oidc.federation.ProviderTrustMarks;
import se.swedenconnect.spring.authnserver.oidc.federation.TrustMarkSource;

/**
 * Tests for the health indicators of the OpenID Provider and the default status order.
 *
 * @author Martin Lindström
 */
class HealthIndicatorsTest {

  private static final String TYPE = "https://id.swedenconnect.se/loa/loa3";

  @Test
  void noTrustMarksIsUp() {
    final Health health = new OidcTrustMarksHealthIndicator(new ProviderTrustMarks("https://op.example.com", List.of()))
        .health();
    assertThat(health.getStatus()).isEqualTo(Status.UP);
  }

  @Test
  void aValidTrustMarkIsUpAndAFailedRenewalIsAWarning() throws Exception {
    final InMemoryProviderTrustMarkStore store = new InMemoryProviderTrustMarkStore();
    final ProviderTrustMarks trustMarks = new ProviderTrustMarks("https://op.example.com", List.of(new TrustMarkSource(
        TYPE, "https://tmi.example.com", URI.create("https://tmi.example.com/trust_mark"),
        new JWKSet(new ECKeyGenerator(Curve.P_256).keyID("k1").generate().toPublicJWK()))),
        store, new HttpFederationClient(), null, ProviderTrustMarks.DEFAULT_RETRY_INTERVAL, Clock.systemUTC());
    final Instant now = Instant.now();
    final ProviderTrustMarkStore.Entry valid = new ProviderTrustMarkStore.Entry("a.b.c", now.plus(Duration.ofDays(1)),
        now.plus(Duration.ofHours(12)), null, now, null, null, 0);
    store.put(TYPE, valid);

    final Health up = new OidcTrustMarksHealthIndicator(trustMarks).health();
    assertThat(up.getStatus()).isEqualTo(Status.UP);
    assertThat(trustMark(up)).containsEntry("published", true).containsKey("expires-at").containsKey("last-fetched")
        .doesNotContainKey("failures");

    store.put(TYPE, valid.failed("connection refused", now, now.plus(Duration.ofMinutes(5))));
    final Health warning = new OidcTrustMarksHealthIndicator(trustMarks).health();
    assertThat(warning.getStatus()).isEqualTo(AuthnServerHealthStatus.WARNING);
    assertThat(trustMark(warning)).containsEntry("published", true).containsEntry("failures", 1)
        .containsEntry("error", "connection refused").containsKey("last-failure");
  }

  @Test
  void noCallsToTheFederationServicesIsUp() {
    final FederationServiceMonitor monitor = new FederationServiceMonitor(new InMemoryFederationServiceStateStore());
    assertThat(new OidcFederationHealthIndicator(monitor).health().getStatus()).isEqualTo(Status.UP);

    monitor.onApplicationEvent(new FederationCallEvent(FederationCallEvent.Call.TRUST_MARK,
        "https://tmi.example.com/trust_mark", "https://tmi.example.com", FederationCallEvent.Outcome.ERROR_RESPONSE,
        null));
    final Health health = new OidcFederationHealthIndicator(monitor).health();
    assertThat(health.getStatus()).isEqualTo(AuthnServerHealthStatus.WARNING);
  }

  @Test
  void theDefaultStatusOrderPutsWarningBetweenUpAndTheFailingStatuses() {
    final StandardEnvironment environment = new StandardEnvironment();
    final HealthStatusEnvironmentPostProcessor processor = new HealthStatusEnvironmentPostProcessor();
    processor.postProcessEnvironment(environment, null);
    processor.postProcessEnvironment(environment, null);
    assertThat(environment.getProperty(HealthStatusEnvironmentPostProcessor.STATUS_ORDER_PROPERTY))
        .isEqualTo("DOWN,OUT_OF_SERVICE,WARNING,UP,UNKNOWN");
    assertThat(environment.getPropertySources().stream()
        .filter(s -> s.getName().equals(HealthStatusEnvironmentPostProcessor.PROPERTY_SOURCE_NAME))).hasSize(1);
    assertThat(processor.getOrder()).isEqualTo(Integer.MAX_VALUE);
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> trustMark(final Health health) {
    return ((List<Map<String, Object>>) health.getDetails().get("trust-marks")).getFirst();
  }

}
