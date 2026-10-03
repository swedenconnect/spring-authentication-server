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

import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.util.StringUtils;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityID;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityType;

import se.swedenconnect.oidf.common.entity.entity.integration.federation.EntityConfigurationRequest;
import se.swedenconnect.oidf.common.entity.entity.integration.federation.FederationClient;
import se.swedenconnect.oidf.common.entity.entity.integration.federation.FederationRequest;
import se.swedenconnect.spring.authnserver.registry.ClientRegistryException;

/**
 * Finds the endpoints that a federation entity publishes in the {@code federation_entity} metadata of its entity
 * configuration, such as {@code federation_resolve_endpoint}, {@code federation_trust_mark_endpoint} and
 * {@code federation_trust_mark_status_endpoint}, see OpenID Federation 1.0, Section 5.1.1.
 * <p>
 * An entity configuration is fetched the first time one of its endpoints is needed, verified with the keys given for
 * the entity, and kept in memory until its {@code exp}. A failed fetch, or an entity configuration that does not
 * publish a needed endpoint, is not kept, so the next need fetches it again. Such a failure is published as a
 * {@link FederationCallEvent} when an event publisher is assigned, in addition to the events that the
 * {@link HttpFederationClient} publishes for the fetch itself.
 * </p>
 *
 * @author Martin Lindström
 */
public class EntityConfigurationEndpoints {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(EntityConfigurationEndpoints.class);

  /** The path, after the entity identifier, where the entity configuration is published. */
  public static final String WELL_KNOWN_PATH = "/.well-known/openid-federation";

  /** The explicit type of an entity configuration. */
  public static final String ENTITY_CONFIGURATION_TYPE = "entity-statement+jwt";

  /** The client making the calls. */
  private final FederationClient federationClient;

  /** The clock, so that tests can control time. */
  private final Clock clock;

  /** The verified entity configurations, keyed by entity identifier. */
  private final Map<String, Entry> entries = new ConcurrentHashMap<>();

  /** Publishes the failures to find an endpoint, or {@code null}. */
  private ApplicationEventPublisher eventPublisher;

  /**
   * Constructor.
   *
   * @param federationClient the client making the calls
   */
  public EntityConfigurationEndpoints(final @NonNull FederationClient federationClient) {
    this(federationClient, Clock.systemUTC());
  }

  /**
   * Constructor.
   *
   * @param federationClient the client making the calls
   * @param clock the clock to use
   */
  public EntityConfigurationEndpoints(final @NonNull FederationClient federationClient, final @NonNull Clock clock) {
    this.federationClient = Objects.requireNonNull(federationClient, "federationClient must not be null");
    this.clock = Objects.requireNonNull(clock, "clock must not be null");
  }

  /**
   * Gets the location of the entity configuration of an entity: its entity identifier, without a trailing
   * {@code /}, followed by {@value #WELL_KNOWN_PATH}.
   *
   * @param entityId the entity identifier
   * @return the location
   */
  public static @NonNull String location(final @NonNull String entityId) {
    final String base = entityId.endsWith("/") ? entityId.substring(0, entityId.length() - 1) : entityId;
    return base + WELL_KNOWN_PATH;
  }

  /**
   * Gets an endpoint that the entity must publish.
   *
   * @param entityId the entity identifier
   * @param keys the federation keys of the entity, that its entity configuration is verified with
   * @param parameter the {@code federation_entity} metadata parameter holding the endpoint
   * @return the endpoint
   * @throws ClientRegistryException if the entity configuration cannot be fetched or verified, or does not publish
   *     the endpoint
   */
  public @NonNull URI getEndpoint(final @NonNull String entityId, final @NonNull JWKSet keys,
      final @NonNull String parameter) throws ClientRegistryException {
    final URI endpoint = this.findEndpoint(entityId, keys, parameter);
    if (endpoint == null) {
      final String message = "The entity configuration of %s does not publish %s".formatted(entityId, parameter);
      this.publishFailure(entityId, message);
      throw new ClientRegistryException(message);
    }
    return endpoint;
  }

  /**
   * Finds an endpoint that the entity may publish.
   *
   * @param entityId the entity identifier
   * @param keys the federation keys of the entity, that its entity configuration is verified with
   * @param parameter the {@code federation_entity} metadata parameter holding the endpoint
   * @return the endpoint, or {@code null} if the entity does not publish it
   * @throws ClientRegistryException if the entity configuration cannot be fetched or verified, or the endpoint is
   *     not a valid URI
   */
  public @Nullable URI findEndpoint(final @NonNull String entityId, final @NonNull JWKSet keys,
      final @NonNull String parameter) throws ClientRegistryException {
    Objects.requireNonNull(entityId, "entityId must not be null");
    Objects.requireNonNull(keys, "keys must not be null");
    Objects.requireNonNull(parameter, "parameter must not be null");

    final Instant now = this.clock.instant();
    Entry entry = this.entries.get(entityId);
    if (entry == null || !entry.expiresAt().isAfter(now)) {
      entry = this.fetch(entityId, keys);
    }
    final Object value = entry.metadata().get(parameter);
    if (!(value instanceof final String endpoint) || !StringUtils.hasText(endpoint)) {
      this.entries.remove(entityId);
      log.debug("The entity configuration of {} does not publish {}", entityId, parameter);
      return null;
    }
    try {
      return URI.create(endpoint);
    }
    catch (final IllegalArgumentException e) {
      this.entries.remove(entityId);
      final String message = "The %s of %s is not a valid URI - %s".formatted(parameter, entityId, e.getMessage());
      this.publishFailure(entityId, message);
      throw new ClientRegistryException(message, e);
    }
  }

  /**
   * Fetches, verifies and keeps the entity configuration of an entity.
   *
   * @param entityId the entity identifier
   * @param keys the federation keys of the entity
   * @return the kept entry
   * @throws ClientRegistryException if the entity configuration cannot be fetched or verified
   */
  private @NonNull Entry fetch(final @NonNull String entityId, final @NonNull JWKSet keys)
      throws ClientRegistryException {
    this.entries.remove(entityId);
    final SignedJWT entityConfiguration;
    try {
      entityConfiguration = this.federationClient.entityConfiguration(
          new FederationRequest<>(new EntityConfigurationRequest(new EntityID(entityId), null)));
    }
    catch (final ClientRegistryException e) {
      throw e;
    }
    catch (final RuntimeException e) {
      throw new ClientRegistryException(
          "Failed to fetch the entity configuration of %s - %s".formatted(entityId, e.getMessage()), e);
    }
    if (entityConfiguration == null) {
      throw new ClientRegistryException("No entity configuration was received from %s".formatted(entityId));
    }
    final JWTClaimsSet claims;
    try {
      claims = FederationJwtVerifier.verify(entityConfiguration, ENTITY_CONFIGURATION_TYPE, keys, entityId, entityId,
          Set.of("iat", "exp"));
    }
    catch (final ClientRegistryException e) {
      this.publishFailure(entityId, e.getMessage());
      throw e;
    }
    final Entry entry = new Entry(federationEntityMetadata(claims), claims.getExpirationTime().toInstant());
    this.entries.put(entityId, entry);
    log.debug("Fetched the entity configuration of {}, valid until {}", entityId, entry.expiresAt());
    return entry;
  }

  /**
   * Gets the {@code federation_entity} metadata of an entity configuration.
   *
   * @param claims the claims of the entity configuration
   * @return the metadata, empty if there is none
   */
  private static @NonNull Map<String, Object> federationEntityMetadata(final @NonNull JWTClaimsSet claims) {
    try {
      final Map<String, Object> metadata = claims.getJSONObjectClaim("metadata");
      final Object federationEntity = metadata != null ? metadata.get(EntityType.FEDERATION_ENTITY.getValue()) : null;
      if (federationEntity instanceof final Map<?, ?> map) {
        final Map<String, Object> result = new HashMap<>();
        map.forEach((key, value) -> result.put(String.valueOf(key), value));
        return result;
      }
    }
    catch (final java.text.ParseException e) {
      log.debug("The metadata of the entity configuration of {} could not be read: {}", claims.getSubject(),
          e.getMessage());
    }
    return Map.of();
  }

  /**
   * Publishes a failure to find an endpoint, if there is an event publisher.
   *
   * @param entityId the entity
   * @param error what went wrong
   */
  private void publishFailure(final @NonNull String entityId, final @NonNull String error) {
    if (this.eventPublisher == null) {
      return;
    }
    try {
      this.eventPublisher.publishEvent(new FederationCallEvent(FederationCallEvent.Call.ENTITY_CONFIGURATION,
          location(entityId), entityId, FederationCallEvent.Outcome.ERROR_RESPONSE, error));
    }
    catch (final RuntimeException e) {
      log.warn("Failed to publish the failure to find an endpoint of {}: {}", entityId, e.getMessage());
    }
  }

  /**
   * Assigns the publisher of the failures to find an endpoint. Without a publisher, nothing is published.
   *
   * @param eventPublisher the event publisher, or {@code null}
   */
  public void setEventPublisher(final @Nullable ApplicationEventPublisher eventPublisher) {
    this.eventPublisher = eventPublisher;
  }

  /**
   * A verified entity configuration, as far as it is needed.
   *
   * @param metadata the {@code federation_entity} metadata
   * @param expiresAt when the entity configuration expires
   */
  private record Entry(@NonNull Map<String, Object> metadata, @NonNull Instant expiresAt) {
  }

}
