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
import java.util.Map;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.util.StringUtils;

import com.nimbusds.jose.jwk.JWKSet;

/**
 * What the OpenID Provider needs to know about the federation it is part of in order to resolve clients and to ask
 * for trust marks.
 * <p>
 * Only what the client registry needs is held here. The settings for joining the federation, such as the entity
 * configuration of the OpenID Provider itself, come later.
 * </p>
 *
 * @param trustAnchor the trust anchor that clients are resolved against
 * @param resolver the resolver service that is asked
 * @param trustMarkIssuers the issuer to ask for a trust mark, keyed by trust mark type. A type that is not in the
 *          map is never asked for
 * @author Martin Lindström
 */
public record FederationSettings(
    @NonNull TrustAnchor trustAnchor,
    @NonNull Resolver resolver,
    @NonNull Map<String, TrustMarkIssuer> trustMarkIssuers) {

  /**
   * Constructor.
   *
   * @param trustAnchor the trust anchor that clients are resolved against
   * @param resolver the resolver service that is asked
   * @param trustMarkIssuers the issuer to ask for a trust mark, keyed by trust mark type
   */
  public FederationSettings {
    Objects.requireNonNull(trustAnchor, "trustAnchor must not be null");
    Objects.requireNonNull(resolver, "resolver must not be null");
    trustMarkIssuers = Map.copyOf(Objects.requireNonNull(trustMarkIssuers, "trustMarkIssuers must not be null"));
    if (resolver.keys() == null && !trustAnchor.entityId().equals(resolver.entityId())) {
      throw new IllegalArgumentException(
          "Keys must be configured for the resolver %s since it is not the trust anchor".formatted(
              resolver.entityId()));
    }
    for (final Map.Entry<String, TrustMarkIssuer> entry : trustMarkIssuers.entrySet()) {
      if (entry.getValue().keys() == null && !trustAnchor.entityId().equals(entry.getValue().entityId())) {
        throw new IllegalArgumentException(
            "Keys must be configured for the trust mark issuer %s since it is not the trust anchor".formatted(
                entry.getValue().entityId()));
      }
    }
  }

  /**
   * Creates settings without any trust mark issuers, meaning that no trust mark is ever asked for on demand.
   *
   * @param trustAnchor the trust anchor that clients are resolved against
   * @param resolver the resolver service that is asked
   * @return a {@link FederationSettings}
   */
  public static @NonNull FederationSettings of(
      final @NonNull TrustAnchor trustAnchor, final @NonNull Resolver resolver) {
    return new FederationSettings(trustAnchor, resolver, Map.of());
  }

  /**
   * Gets the keys that a resolve response is verified with. They are the trust anchor's keys when the resolver runs
   * at the trust anchor, and the resolver's own keys otherwise.
   *
   * @return the verification keys of the resolver
   */
  public @NonNull JWKSet getResolverKeys() {
    return this.resolver.keys() != null ? this.resolver.keys() : this.trustAnchor.keys();
  }

  /**
   * Gets the issuer to ask for a trust mark of the given type.
   *
   * @param trustMarkType the trust mark type
   * @return a {@link TrustMarkIssuer}, or {@code null} if no issuer is configured for the type
   */
  public @Nullable TrustMarkIssuer getTrustMarkIssuer(final @NonNull String trustMarkType) {
    return this.trustMarkIssuers.get(Objects.requireNonNull(trustMarkType, "trustMarkType must not be null"));
  }

  /**
   * Gets the keys that a trust mark from the given issuer is verified with. They are the trust anchor's keys when
   * the issuer is the trust anchor, and the issuer's own keys otherwise.
   *
   * @param issuer the trust mark issuer
   * @return the verification keys of the issuer
   */
  public @NonNull JWKSet getTrustMarkIssuerKeys(final @NonNull TrustMarkIssuer issuer) {
    Objects.requireNonNull(issuer, "issuer must not be null");
    return issuer.keys() != null ? issuer.keys() : this.trustAnchor.keys();
  }

  /**
   * The trust anchor of the federation.
   *
   * @param entityId the entity identifier of the trust anchor
   * @param keys the federation keys of the trust anchor
   */
  public record TrustAnchor(@NonNull String entityId, @NonNull JWKSet keys) {

    /**
     * Constructor.
     *
     * @param entityId the entity identifier of the trust anchor
     * @param keys the federation keys of the trust anchor
     */
    public TrustAnchor {
      Objects.requireNonNull(keys, "keys must not be null");
      if (!StringUtils.hasText(entityId)) {
        throw new IllegalArgumentException("entityId must be set and not empty");
      }
    }

  }

  /**
   * The resolver service that client metadata is resolved through.
   *
   * @param entityId the entity identifier of the resolver
   * @param endpoint the resolve endpoint of the resolver
   * @param keys the federation keys of the resolver, or {@code null} when the resolver is the trust anchor and the
   *          trust anchor keys are used
   */
  public record Resolver(@NonNull String entityId, @NonNull URI endpoint, @Nullable JWKSet keys) {

    /**
     * Constructor.
     *
     * @param entityId the entity identifier of the resolver
     * @param endpoint the resolve endpoint of the resolver
     * @param keys the federation keys of the resolver, or {@code null}
     */
    public Resolver {
      Objects.requireNonNull(endpoint, "endpoint must not be null");
      if (!StringUtils.hasText(entityId)) {
        throw new IllegalArgumentException("entityId must be set and not empty");
      }
    }

  }

  /**
   * A trust mark issuer that is asked for trust marks on demand.
   *
   * @param entityId the entity identifier of the issuer
   * @param endpoint the trust mark endpoint of the issuer
   * @param keys the federation keys of the issuer, or {@code null} when the issuer is the trust anchor and the trust
   *          anchor keys are used
   */
  public record TrustMarkIssuer(@NonNull String entityId, @NonNull URI endpoint, @Nullable JWKSet keys) {

    /**
     * Constructor.
     *
     * @param entityId the entity identifier of the issuer
     * @param endpoint the trust mark endpoint of the issuer
     * @param keys the federation keys of the issuer, or {@code null}
     */
    public TrustMarkIssuer {
      Objects.requireNonNull(endpoint, "endpoint must not be null");
      if (!StringUtils.hasText(entityId)) {
        throw new IllegalArgumentException("entityId must be set and not empty");
      }
    }

  }

}
