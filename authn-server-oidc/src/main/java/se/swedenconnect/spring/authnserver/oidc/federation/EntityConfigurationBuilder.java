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
package se.swedenconnect.spring.authnserver.oidc.federation;

import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Supplier;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.security.config.Customizer;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityType;

import se.swedenconnect.spring.authnserver.oidc.keys.FederationKey;
import se.swedenconnect.spring.authnserver.oidc.keys.FederationKeys;

/**
 * Builds and signs the entity configuration of the OpenID Provider, as described in OpenID Federation 1.0, Section 3.
 * <p>
 * The entity configuration holds {@code iss} and {@code sub}, both the entity identifier, {@code iat}, {@code exp},
 * {@code jwks} with the federation keys, {@code authority_hints}, {@code trust_marks} when there are any, and
 * {@code metadata} with the {@code openid_provider} entity type only. The OpenID Provider is a leaf entity and never
 * publishes {@code federation_entity} metadata.
 * </p>
 * <p>
 * The additional parameters are applied to the built claims: a {@code metadata} parameter is merged into the metadata,
 * per entity type and parameter, and any other parameter is set as a claim. The customizer gets the claims last, as a
 * mutable map where {@code metadata} and its entity types are mutable maps too, and may change anything. {@code iss},
 * {@code sub}, {@code iat} and {@code exp} are set after the customizer has run.
 * </p>
 * <p>
 * The entity configuration is signed with the active federation key, and has the type
 * {@value #ENTITY_STATEMENT_TYPE}.
 * </p>
 *
 * @author Martin Lindström
 */
public class EntityConfigurationBuilder {

  /** The explicit type of an entity statement. */
  public static final String ENTITY_STATEMENT_TYPE = "entity-statement+jwt";

  /** The claim holding the metadata. */
  public static final String METADATA = "metadata";

  /** The entity identifier. */
  private final String entityId;

  /** The authority hints. */
  private final List<String> authorityHints;

  /** Gives the federation keys. */
  private final Supplier<FederationKeys> keys;

  /** Gives the trust marks to publish. */
  private final Supplier<List<TrustMarkEntry>> trustMarks;

  /** The {@code openid_provider} metadata. */
  private final String providerMetadata;

  /** The lifetime of the entity configuration. */
  private final Duration lifetime;

  /** Parameters applied to the built claims. */
  private Map<String, Object> additionalParameters;

  /** Gets the claims last. */
  private Customizer<Map<String, Object>> customizer = Customizer.withDefaults();

  /**
   * Constructor.
   *
   * @param entityId the entity identifier
   * @param authorityHints the entity identifiers of the immediate superiors, at least one
   * @param keys gives the federation keys
   * @param trustMarks gives the trust marks to publish
   * @param providerMetadata the {@code openid_provider} metadata
   * @param lifetime the lifetime of the entity configuration
   */
  public EntityConfigurationBuilder(final @NonNull String entityId, final @NonNull List<String> authorityHints,
      final @NonNull Supplier<FederationKeys> keys, final @NonNull Supplier<List<TrustMarkEntry>> trustMarks,
      final @NonNull Map<String, Object> providerMetadata, final @NonNull Duration lifetime) {
    this.entityId = Objects.requireNonNull(entityId, "entityId must not be null");
    this.authorityHints = List.copyOf(Objects.requireNonNull(authorityHints, "authorityHints must not be null"));
    if (this.authorityHints.isEmpty()) {
      throw new IllegalArgumentException("At least one authority hint is required");
    }
    this.keys = Objects.requireNonNull(keys, "keys must not be null");
    this.trustMarks = Objects.requireNonNull(trustMarks, "trustMarks must not be null");
    this.providerMetadata = JSONObjectUtils.toJSONString(
        Objects.requireNonNull(providerMetadata, "providerMetadata must not be null"));
    this.lifetime = Objects.requireNonNull(lifetime, "lifetime must not be null");
    if (lifetime.isZero() || lifetime.isNegative()) {
      throw new IllegalArgumentException("lifetime must be a positive duration");
    }
  }

  /**
   * Assigns parameters that are applied to the built claims. A {@code metadata} parameter holding a map of entity types
   * is merged into the metadata, per entity type and parameter; any other parameter is set as a claim.
   *
   * @param additionalParameters the parameters, or {@code null}
   */
  public void setAdditionalParameters(final @Nullable Map<String, Object> additionalParameters) {
    this.additionalParameters = additionalParameters;
  }

  /**
   * Assigns a customizer that gets the claims, as a mutable map, before they are signed.
   *
   * @param customizer the customizer
   */
  public void setCustomizer(final @NonNull Customizer<Map<String, Object>> customizer) {
    this.customizer = Objects.requireNonNull(customizer, "customizer must not be null");
  }

  /**
   * Gets the lifetime of the entity configuration.
   *
   * @return the lifetime
   */
  public @NonNull Duration getLifetime() {
    return this.lifetime;
  }

  /**
   * Gets what the content of the entity configuration depends on that may change while the server runs: the key IDs
   * and states of the federation keys, and the trust marks. An entity configuration built when the value was different
   * is out of date.
   *
   * @return the content state
   */
  public @NonNull Object getContentState() {
    return List.of(this.keys.get().getKeyStates(), this.trustMarks.get());
  }

  /**
   * Builds and signs the entity configuration.
   *
   * @param now the issuance time
   * @return the signed entity configuration
   * @throws IllegalStateException if the entity configuration cannot be built or signed
   */
  public @NonNull SignedJWT build(final @NonNull Instant now) {
    final FederationKeys federationKeys = this.keys.get();
    final Map<String, Object> claims = new LinkedHashMap<>();
    claims.put("iss", this.entityId);
    claims.put("sub", this.entityId);
    claims.put("jwks", federationKeys.getPublishedKeys().toJSONObject(true));
    claims.put("authority_hints", new ArrayList<>(this.authorityHints));
    final List<TrustMarkEntry> marks = this.trustMarks.get();
    if (!marks.isEmpty()) {
      claims.put("trust_marks", new ArrayList<>(marks.stream().map(TrustMarkEntry::toJson).toList()));
    }
    final Map<String, Object> metadata = new LinkedHashMap<>();
    metadata.put(EntityType.OPENID_PROVIDER.getValue(), this.copyProviderMetadata());
    claims.put(METADATA, metadata);

    this.applyAdditionalParameters(claims);
    this.customizer.customize(claims);

    if (claims.get(METADATA) instanceof final Map<?, ?> finalMetadata
        && finalMetadata.containsKey(EntityType.FEDERATION_ENTITY.getValue())) {
      throw new IllegalStateException("The entity configuration of the OpenID Provider must not hold "
          + "federation_entity metadata - it is a leaf entity");
    }
    claims.put("iss", this.entityId);
    claims.put("sub", this.entityId);
    claims.put("iat", now.getEpochSecond());
    claims.put("exp", now.plus(this.lifetime).getEpochSecond());

    try {
      final FederationKey key = federationKeys.getSigningKey();
      return key.sign(JWTClaimsSet.parse(claims), new JOSEObjectType(ENTITY_STATEMENT_TYPE));
    }
    catch (final ParseException | JOSEException | RuntimeException e) {
      throw new IllegalStateException("Failed to create the entity configuration - " + e.getMessage(), e);
    }
  }

  /**
   * Applies the additional parameters to the claims.
   *
   * @param claims the claims
   */
  @SuppressWarnings("unchecked")
  private void applyAdditionalParameters(final @NonNull Map<String, Object> claims) {
    if (this.additionalParameters == null) {
      return;
    }
    for (final Map.Entry<String, Object> parameter : this.additionalParameters.entrySet()) {
      if (METADATA.equals(parameter.getKey()) && parameter.getValue() instanceof final Map<?, ?> added) {
        final Map<String, Object> metadata = (Map<String, Object>) claims.get(METADATA);
        added.forEach((type, value) -> {
          final Object existing = metadata.get(String.valueOf(type));
          if (existing instanceof final Map<?, ?> existingMap && value instanceof final Map<?, ?> valueMap) {
            final Map<String, Object> merged = new LinkedHashMap<>((Map<String, Object>) existingMap);
            valueMap.forEach((k, v) -> merged.put(String.valueOf(k), v));
            metadata.put(String.valueOf(type), merged);
          }
          else {
            metadata.put(String.valueOf(type), value);
          }
        });
      }
      else {
        claims.put(parameter.getKey(), parameter.getValue());
      }
    }
  }

  /**
   * Creates a mutable copy of the {@code openid_provider} metadata.
   *
   * @return the metadata
   */
  private @NonNull Map<String, Object> copyProviderMetadata() {
    try {
      return new LinkedHashMap<>(JSONObjectUtils.parse(this.providerMetadata));
    }
    catch (final ParseException e) {
      throw new IllegalStateException("Invalid OpenID Provider metadata", e);
    }
  }

}
