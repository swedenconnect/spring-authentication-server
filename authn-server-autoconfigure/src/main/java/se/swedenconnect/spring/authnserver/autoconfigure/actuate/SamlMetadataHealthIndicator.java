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

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.springframework.boot.health.contributor.AbstractHealthIndicator;
import org.springframework.boot.health.contributor.Health;

import se.swedenconnect.spring.authnserver.autoconfigure.ConfiguredAuthnServer;
import se.swedenconnect.spring.authnserver.saml.metadata.ManagedMetadataSource;
import se.swedenconnect.spring.authnserver.saml.metadata.SamlMetadataBackend;

/**
 * Health of the SAML metadata sources.
 * <p>
 * Each source reports whether its latest download succeeded and how old its metadata is. A source whose latest
 * download failed gives {@link AuthnServerHealthStatus#WARNING}, since the Identity Provider keeps using the metadata
 * it has. When no source holds a single Service Provider, the status is {@code OUT_OF_SERVICE}. A source that is
 * queried with MDQ cannot tell how many Service Providers it has, and does not count as empty.
 * </p>
 *
 * @author Martin Lindström
 */
public class SamlMetadataHealthIndicator extends AbstractHealthIndicator {

  /** The configured server. */
  private final ConfiguredAuthnServer server;

  /** The clock. */
  private final Clock clock;

  /**
   * Constructor.
   *
   * @param server the configured server
   */
  public SamlMetadataHealthIndicator(final @NonNull ConfiguredAuthnServer server) {
    this(server, Clock.systemUTC());
  }

  /**
   * Constructor.
   *
   * @param server the configured server
   * @param clock the clock to use
   */
  public SamlMetadataHealthIndicator(final @NonNull ConfiguredAuthnServer server, final @NonNull Clock clock) {
    super("SAML metadata health check failed");
    this.server = Objects.requireNonNull(server, "server must not be null");
    this.clock = Objects.requireNonNull(clock, "clock must not be null");
  }

  /** {@inheritDoc} */
  @Override
  protected void doHealthCheck(final Health.@NonNull Builder builder) {
    final List<SamlMetadataBackend> backends = this.server.getClientRegistryBackends(SamlMetadataBackend.class);
    if (backends.isEmpty()) {
      builder.unknown().withDetail("error", "No SAML metadata sources are configured");
      return;
    }
    final Instant now = this.clock.instant();
    final List<Map<String, Object>> sources = new ArrayList<>();
    boolean failing = false;
    boolean anyListable = false;
    int serviceProviders = 0;
    for (final SamlMetadataBackend backend : backends) {
      for (final ManagedMetadataSource source : backend.getMetadataSources()) {
        final Map<String, Object> s = new LinkedHashMap<>();
        s.put("name", source.getName());
        final Boolean success = source.wasLastRefreshSuccessful();
        if (source.getLastRefresh() != null) {
          s.put("last-download", source.getLastRefresh().toString());
        }
        if (success != null) {
          s.put("last-download-successful", success);
        }
        final Instant loaded = source.getLastSuccessfulRefresh() != null
            ? source.getLastSuccessfulRefresh()
            : source.getLastUpdate();
        if (loaded != null) {
          s.put("loaded-at", loaded.toString());
          s.put("age", Duration.between(loaded, now).withNanos(0).toString());
        }
        if (source.isListable()) {
          anyListable = true;
          final int count = source.getServiceProviders().size();
          serviceProviders += count;
          s.put("service-providers", count);
        }
        if (Boolean.FALSE.equals(success)) {
          failing = true;
          s.put("error", Objects.requireNonNullElse(source.getLastFailure(), "The latest download failed"));
        }
        sources.add(s);
      }
    }
    builder.withDetail("sources", sources);
    if (anyListable && serviceProviders == 0) {
      builder.outOfService().withDetail("error", "No SAML metadata for any Service Provider is available");
    }
    else if (failing) {
      builder.status(AuthnServerHealthStatus.WARNING);
    }
    else {
      builder.up();
    }
  }

}
