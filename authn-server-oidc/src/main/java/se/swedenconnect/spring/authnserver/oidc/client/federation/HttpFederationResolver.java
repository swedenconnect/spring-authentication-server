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

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;

import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
 * trust anchor, and with the resolver's own keys otherwise.
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

  /**
   * Constructor using an {@link HttpFederationClient} with the default settings.
   *
   * @param settings the settings of the federation
   */
  public HttpFederationResolver(final @Nonnull FederationSettings settings) {
    this(settings, new HttpFederationClient());
  }

  /**
   * Constructor.
   *
   * @param settings the settings of the federation
   * @param federationClient the client making the call
   */
  public HttpFederationResolver(
      final @Nonnull FederationSettings settings, final @Nonnull FederationClient federationClient) {
    this.settings = Objects.requireNonNull(settings, "settings must not be null");
    this.federationClient = Objects.requireNonNull(federationClient, "federationClient must not be null");
  }

  /** {@inheritDoc} */
  @Override
  public @Nullable ResolvedClient resolve(final @Nonnull String clientId) throws ClientRegistryException {
    Objects.requireNonNull(clientId, "clientId must not be null");

    final ResolveRequest request = new ResolveRequest(clientId, this.settings.trustAnchor().entityId(),
        EntityType.OPENID_RELYING_PARTY.getValue(), Boolean.FALSE);
    final SignedJWT response = this.federationClient.resolve(new FederationRequest<>(request,
        Map.of(HttpFederationClient.FEDERATION_RESOLVE_ENDPOINT,
            this.settings.resolver().endpoint().toString())));

    if (response == null) {
      log.debug("The resolver does not know the client '{}'", clientId);
      return null;
    }
    final JWTClaimsSet claims = FederationJwtVerifier.verify(response, RESOLVE_RESPONSE_TYPE,
        this.settings.getResolverKeys(), this.settings.resolver().entityId(), clientId, Set.of("exp", "metadata"));

    final OIDCClientMetadata metadata = clientMetadata(claims, clientId);
    if (metadata == null) {
      return null;
    }
    final Instant expiresAt = claims.getExpirationTime().toInstant();
    log.debug("Resolved the client '{}', valid until {}", clientId, expiresAt);
    return new ResolvedClient(clientId, metadata, trustMarkTypes(claims), expiresAt);
  }

  /**
   * Gets the relying party metadata of the resolve response.
   *
   * @param claims the claims of the resolve response
   * @param clientId the {@code client_id} of the client
   * @return the client metadata, or {@code null} if the entity is not an OpenID Connect client
   * @throws ClientRegistryException if the metadata cannot be parsed
   */
  private static @Nullable OIDCClientMetadata clientMetadata(
      final @Nonnull JWTClaimsSet claims, final @Nonnull String clientId) throws ClientRegistryException {
    try {
      final Map<String, Object> metadata = claims.getJSONObjectClaim("metadata");
      final Object relyingParty = metadata != null
          ? metadata.get(EntityType.OPENID_RELYING_PARTY.getValue())
          : null;
      if (!(relyingParty instanceof final Map<?, ?> map)) {
        log.debug("The resolved entity '{}' is not an OpenID Connect client", clientId);
        return null;
      }
      final JSONObject json = new JSONObject();
      map.forEach((key, value) -> json.put(String.valueOf(key), value));
      return OIDCClientMetadata.parse(json);
    }
    catch (final Exception e) {
      throw new ClientRegistryException(
          "Failed to parse the metadata of the resolve response for '%s' - %s".formatted(clientId, e.getMessage()), e);
    }
  }

  /**
   * Gets the types of the trust marks that the resolve response holds. The resolver has checked them, so the type is
   * all that is kept.
   *
   * @param claims the claims of the resolve response
   * @return the trust mark types
   */
  private static @Nonnull Set<String> trustMarkTypes(final @Nonnull JWTClaimsSet claims) {
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

}
