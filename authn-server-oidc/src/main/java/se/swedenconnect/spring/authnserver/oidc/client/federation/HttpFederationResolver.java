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
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityType;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import net.minidev.json.JSONObject;
import se.swedenconnect.oidf.common.entity.entity.integration.federation.FederationClient;
import se.swedenconnect.oidf.common.entity.entity.integration.federation.FederationRequest;
import se.swedenconnect.oidf.common.entity.entity.integration.federation.ResolveRequest;
import se.swedenconnect.spring.authnserver.registry.ClientRegistryException;

/**
 * A {@link FederationResolver} that asks an external resolver service, see
 * <a href="https://openid.net/specs/openid-federation-1_0.html#section-8.3">OpenID Federation 1.0, Section 8.3</a>.
 * <p>
 * The resolve response is a signed JWT. It is verified with the trust anchor's keys when the resolver runs at the
 * trust anchor, and with the resolver's own keys otherwise. When no resolve endpoint is configured, the
 * {@code federation_resolve_endpoint} that the resolver publishes in its entity configuration is used.
 * </p>
 * <p>
 * A client is resolved asking for its relying party metadata only. An entity of the federation, see
 * {@link #resolveEntity(String)}, is resolved asking for both its relying party and its federation entity metadata.
 * </p>
 * <p>
 * Relying party metadata that cannot be parsed does not make the resolution fail. The client is resolved with empty
 * metadata and the reason, see {@link ResolvedClient#metadataError()}, so that it can be marked as invalid. The
 * client's Federation Entity Keys are read from its entity configuration, which comes first in the
 * {@code trust_chain} of the response, see
 * <a href="https://openid.net/specs/openid-federation-1_0.html#section-8.3.2">OpenID Federation 1.0, Section
 * 8.3.2</a>.
 * </p>
 *
 * @author Martin Lindström
 */
public class HttpFederationResolver implements FederationResolver {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(HttpFederationResolver.class);

  /** The explicit type of a resolve response. */
  public static final String RESOLVE_RESPONSE_TYPE = "resolve-response+jwt";

  /** The settings of the federation. */
  private final FederationSettings settings;

  /** The client making the call. */
  private final FederationClient federationClient;

  /** Finds the resolve endpoint when none is configured. */
  private final EntityConfigurationEndpoints endpoints;

  /**
   * Constructor using an {@link HttpFederationClient} with the default settings.
   *
   * @param settings the settings of the federation
   */
  public HttpFederationResolver(final @NonNull FederationSettings settings) {
    this(settings, new HttpFederationClient());
  }

  /**
   * Constructor.
   *
   * @param settings the settings of the federation
   * @param federationClient the client making the call
   */
  public HttpFederationResolver(
      final @NonNull FederationSettings settings, final @NonNull FederationClient federationClient) {
    this(settings, federationClient, new EntityConfigurationEndpoints(federationClient));
  }

  /**
   * Constructor.
   *
   * @param settings the settings of the federation
   * @param federationClient the client making the call
   * @param endpoints finds the resolve endpoint in the resolver's entity configuration when none is configured
   */
  public HttpFederationResolver(final @NonNull FederationSettings settings,
      final @NonNull FederationClient federationClient, final @NonNull EntityConfigurationEndpoints endpoints) {
    this.settings = Objects.requireNonNull(settings, "settings must not be null");
    this.federationClient = Objects.requireNonNull(federationClient, "federationClient must not be null");
    this.endpoints = Objects.requireNonNull(endpoints, "endpoints must not be null");
  }

  /** {@inheritDoc} */
  @Override
  public @Nullable ResolvedClient resolve(final @NonNull String clientId) throws ClientRegistryException {
    Objects.requireNonNull(clientId, "clientId must not be null");

    final JWTClaimsSet claims = this.resolveClaims(clientId, List.of(EntityType.OPENID_RELYING_PARTY.getValue()));
    if (claims == null) {
      log.debug("The resolver does not know the client '{}'", clientId);
      return null;
    }
    final ClientMetadata metadata = clientMetadata(claims, clientId);
    if (metadata == null) {
      return null;
    }
    final Instant expiresAt = claims.getExpirationTime().toInstant();
    log.debug("Resolved the client '{}', valid until {}", clientId, expiresAt);
    return new ResolvedClient(clientId, metadata.metadata(), trustMarkTypes(claims), expiresAt, metadata.error(),
        entityKeys(claims, clientId));
  }

  /**
   * Resolves an entity asking for its relying party and its federation entity metadata. The
   * {@code federation_list_endpoint} is read from the federation entity metadata.
   */
  @Override
  public @Nullable ResolvedEntity resolveEntity(final @NonNull String entityId) throws ClientRegistryException {
    Objects.requireNonNull(entityId, "entityId must not be null");

    final JWTClaimsSet claims = this.resolveClaims(entityId,
        List.of(EntityType.OPENID_RELYING_PARTY.getValue(), EntityType.FEDERATION_ENTITY.getValue()));
    if (claims == null) {
      log.debug("The resolver does not know the entity '{}'", entityId);
      return null;
    }
    final Map<String, Object> federationEntity = federationEntityMetadata(claims, entityId);
    final ClientMetadata metadata = clientMetadata(claims, entityId);
    if (metadata == null && federationEntity == null) {
      log.debug("The resolved entity '{}' has none of the asked for entity types", entityId);
      return null;
    }
    final String listEndpoint = federationEntity != null
        && federationEntity.get(HttpFederationClient.FEDERATION_LIST_ENDPOINT) instanceof final String value
        && !value.isBlank()
        ? value
        : null;
    final Instant expiresAt = claims.getExpirationTime().toInstant();
    log.debug("Resolved the entity '{}', valid until {}", entityId, expiresAt);
    return new ResolvedEntity(entityId, metadata != null ? metadata.metadata() : null, listEndpoint,
        trustMarkTypes(claims), expiresAt, metadata != null ? metadata.error() : null, entityKeys(claims, entityId));
  }

  /**
   * Makes a resolve request and verifies the response.
   *
   * @param entityId the entity identifier of the subject
   * @param entityTypes the entity types to ask for
   * @return the claims of the verified response, or {@code null} if the resolver does not know the entity
   * @throws ClientRegistryException if the resolution fails or the response does not verify
   */
  private @Nullable JWTClaimsSet resolveClaims(final @NonNull String entityId, final @NonNull List<String> entityTypes)
      throws ClientRegistryException {
    final ResolveRequest request =
        new ResolveRequest(entityId, this.settings.trustAnchor().entityId(), entityTypes, Boolean.FALSE);
    final URI endpoint = this.settings.resolver().endpoint() != null
        ? this.settings.resolver().endpoint()
        : this.endpoints.getEndpoint(this.settings.resolver().entityId(), this.settings.getResolverKeys(),
            HttpFederationClient.FEDERATION_RESOLVE_ENDPOINT);
    final SignedJWT response = this.federationClient.resolve(new FederationRequest<>(request,
        Map.of(HttpFederationClient.FEDERATION_RESOLVE_ENDPOINT, endpoint.toString())));
    if (response == null) {
      return null;
    }
    return FederationJwtVerifier.verify(response, RESOLVE_RESPONSE_TYPE,
        this.settings.getResolverKeys(), this.settings.resolver().entityId(), entityId, Set.of("exp", "metadata"));
  }

  /**
   * Gets the federation entity metadata of the resolve response.
   *
   * @param claims the claims of the resolve response
   * @param entityId the entity identifier
   * @return the federation entity metadata, or {@code null} if the response has none
   * @throws ClientRegistryException if the metadata cannot be read
   */
  private static @Nullable Map<String, Object> federationEntityMetadata(
      final @NonNull JWTClaimsSet claims, final @NonNull String entityId) throws ClientRegistryException {
    try {
      final Map<String, Object> metadata = claims.getJSONObjectClaim("metadata");
      final Object federationEntity = metadata != null ? metadata.get(EntityType.FEDERATION_ENTITY.getValue()) : null;
      if (!(federationEntity instanceof final Map<?, ?> map)) {
        return null;
      }
      final Map<String, Object> result = new LinkedHashMap<>();
      map.forEach((key, value) -> result.put(String.valueOf(key), value));
      return result;
    }
    catch (final java.text.ParseException e) {
      throw new ClientRegistryException(
          "Failed to read the metadata of the resolve response for '%s' - %s".formatted(entityId, e.getMessage()), e);
    }
  }

  /**
   * Gets the relying party metadata of the resolve response. Metadata that cannot be parsed gives empty metadata and
   * the reason.
   *
   * @param claims the claims of the resolve response
   * @param clientId the {@code client_id} of the client
   * @return the client metadata, or {@code null} if the entity is not an OpenID Connect client
   * @throws ClientRegistryException if the {@code metadata} claim cannot be read
   */
  private static @Nullable ClientMetadata clientMetadata(
      final @NonNull JWTClaimsSet claims, final @NonNull String clientId) throws ClientRegistryException {
    final Map<String, Object> metadata;
    try {
      metadata = claims.getJSONObjectClaim("metadata");
    }
    catch (final java.text.ParseException e) {
      throw new ClientRegistryException(
          "Failed to read the metadata of the resolve response for '%s' - %s".formatted(clientId, e.getMessage()), e);
    }
    final Object relyingParty = metadata != null ? metadata.get(EntityType.OPENID_RELYING_PARTY.getValue()) : null;
    if (relyingParty == null) {
      log.debug("The resolved entity '{}' is not an OpenID Connect client", clientId);
      return null;
    }
    if (!(relyingParty instanceof final Map<?, ?> map)) {
      log.debug("The relying party metadata of '{}' is not a JSON object", clientId);
      return new ClientMetadata(new OIDCClientMetadata(), "the openid_relying_party metadata is not a JSON object");
    }
    try {
      final JSONObject json = new JSONObject();
      map.forEach((key, value) -> json.put(String.valueOf(key), value));
      return new ClientMetadata(OIDCClientMetadata.parse(json), null);
    }
    catch (final Exception e) {
      log.debug("The relying party metadata of '{}' cannot be parsed: {}", clientId, e.getMessage());
      return new ClientMetadata(new OIDCClientMetadata(), Objects.requireNonNullElse(e.getMessage(),
          e.getClass().getSimpleName()));
    }
  }

  /**
   * Gets the Federation Entity Keys of the subject from its entity configuration, which comes first in the
   * {@code trust_chain} of the resolve response. The resolver has verified the trust chain.
   *
   * @param claims the claims of the resolve response
   * @param entityId the entity identifier of the subject
   * @return the keys, or {@code null} if the response has no usable {@code trust_chain}
   */
  static @Nullable JWKSet entityKeys(final @NonNull JWTClaimsSet claims, final @NonNull String entityId) {
    try {
      final List<Object> chain = claims.getListClaim("trust_chain");
      if (chain == null || chain.isEmpty() || !(chain.getFirst() instanceof final String first)) {
        log.debug("The resolve response for '{}' has no trust_chain", entityId);
        return null;
      }
      final JWTClaimsSet configuration = SignedJWT.parse(first).getJWTClaimsSet();
      if (!entityId.equals(configuration.getIssuer()) || !entityId.equals(configuration.getSubject())) {
        log.debug("The trust_chain of the resolve response for '{}' does not start with its entity configuration",
            entityId);
        return null;
      }
      final Map<String, Object> jwks = configuration.getJSONObjectClaim("jwks");
      final JWKSet keys = jwks != null ? JWKSet.parse(jwks) : null;
      return keys != null && !keys.isEmpty() ? keys : null;
    }
    catch (final java.text.ParseException | RuntimeException e) {
      log.debug("The trust_chain of the resolve response for '{}' cannot be read: {}", entityId, e.getMessage());
      return null;
    }
  }

  /**
   * Gets the types of the trust marks that the resolve response holds. The resolver has checked them, so the type is
   * all that is kept.
   *
   * @param claims the claims of the resolve response
   * @return the trust mark types
   */
  private static @NonNull Set<String> trustMarkTypes(final @NonNull JWTClaimsSet claims) {
    final List<Object> trustMarks;
    try {
      trustMarks = claims.getListClaim("trust_marks");
    }
    catch (final java.text.ParseException e) {
      log.warn("The trust_marks claim of the resolve response for '{}' could not be read - it is ignored",
          claims.getSubject());
      return Set.of();
    }
    if (trustMarks == null) {
      return Set.of();
    }
    final Set<String> types = new LinkedHashSet<>();
    for (final Object trustMark : trustMarks) {
      if (trustMark instanceof final Map<?, ?> map && map.get("trust_mark_type") instanceof final String type) {
        types.add(type);
      }
    }
    return types;
  }

  /**
   * The relying party metadata of a resolve response.
   *
   * @param metadata the metadata, empty if it cannot be parsed
   * @param error why the metadata cannot be parsed, or {@code null} if it can
   */
  private record ClientMetadata(@NonNull OIDCClientMetadata metadata, @Nullable String error) {
  }

}
