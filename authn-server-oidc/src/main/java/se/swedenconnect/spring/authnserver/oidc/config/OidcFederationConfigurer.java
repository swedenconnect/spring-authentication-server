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
package se.swedenconnect.spring.authnserver.oidc.config;

import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import se.swedenconnect.oidf.common.entity.entity.integration.federation.FederationClient;
import se.swedenconnect.spring.authnserver.oidc.client.federation.HttpFederationClient;
import se.swedenconnect.spring.authnserver.oidc.federation.EntityConfigurationBuilder;
import se.swedenconnect.spring.authnserver.oidc.federation.EntityConfigurationContainer;
import se.swedenconnect.spring.authnserver.oidc.federation.ProviderTrustMarks;
import se.swedenconnect.spring.authnserver.oidc.federation.TrustMarkSource;
import se.swedenconnect.spring.authnserver.oidc.federation.TrustMarkState;
import se.swedenconnect.spring.authnserver.oidc.keys.FederationKey;
import se.swedenconnect.spring.authnserver.oidc.keys.FederationKeys;
import se.swedenconnect.spring.authnserver.oidc.web.OidcEntityConfigurationEndpointFilter;

/**
 * Configurer for the OpenID Provider as a member of an OpenID Federation: its entity configuration, its federation
 * keys and its own trust marks. Federation is off unless it has been {@link #enabled(boolean) enabled}.
 * <p>
 * The entity identifier is the issuer. The entity configuration is published at the issuer followed by
 * {@value #WELL_KNOWN_PATH}, as OpenID Federation 1.0, Section 9, says, see {@link EntityConfigurationBuilder} for
 * its contents. Its {@code openid_provider} metadata is the discovery document, as it is after the discovery
 * additional parameters and customizer have been applied, with the descriptive parameters of
 * {@link OidcProviderConfigurer#getEntityMetadata()} and {@code client_registration_types_supported} added unless the
 * discovery document already has them. The additional parameters and the customizer of this configurer are applied
 * last, and only to the entity configuration.
 * </p>
 * <p>
 * When federation is enabled, at least one federation key and at least one authority hint are required, and the
 * descriptive parameters must hold at least one e-mail address in {@code contacts} and an HTTPS {@code logo_uri}.
 * </p>
 *
 * @author Martin Lindström
 */
public class OidcFederationConfigurer {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(OidcFederationConfigurer.class);

  /** The path, relative to the entity identifier, where the entity configuration is published, {@value}. */
  public static final String WELL_KNOWN_PATH = "/.well-known/openid-federation";

  /** The default lifetime of the entity configuration: one day. */
  public static final Duration DEFAULT_ENTITY_CONFIGURATION_LIFETIME = Duration.ofDays(1);

  /** The metadata parameter telling the client registration types. */
  public static final String CLIENT_REGISTRATION_TYPES_SUPPORTED = "client_registration_types_supported";

  /** The OIDC configurer. */
  private final OidcProviderConfigurer oidcConfigurer;

  /** Whether federation is enabled. */
  private boolean enabled = false;

  /** The authority hints. */
  private List<String> authorityHints;

  /** The federation keys. */
  private List<FederationKey> keys;

  /** The lifetime of the entity configuration. */
  private Duration entityConfigurationLifetime = DEFAULT_ENTITY_CONFIGURATION_LIFETIME;

  /** Parameters applied to the entity configuration. */
  private Map<String, Object> additionalParameters;

  /** Gets the claims of the entity configuration last. */
  private Customizer<Map<String, Object>> entityConfigurationCustomizer = Customizer.withDefaults();

  /** Where the trust marks of the OpenID Provider are fetched. */
  private List<TrustMarkSource> trustMarks;

  /** The directory where the trust marks are stored, or {@code null}. */
  private Path trustMarkCacheDirectory;

  /** The interval between two attempts to fetch a trust mark after a failure. */
  private Duration trustMarkRetryInterval = ProviderTrustMarks.DEFAULT_RETRY_INTERVAL;

  /** The trust marks, if assigned by the application. */
  private ProviderTrustMarks providerTrustMarks;

  /** The client making the federation calls, or {@code null} for the default. */
  private FederationClient federationClient;

  /** The federation keys, created at initialization. */
  private FederationKeys federationKeys;

  /** The trust marks that are used, created when the configurer is applied. */
  private ProviderTrustMarks activeTrustMarks;

  /** The request matcher for the entity configuration endpoint. */
  private RequestMatcher requestMatcher;

  /** Holds the entity configuration, created when the configurer is applied. */
  private EntityConfigurationContainer container;

  /**
   * Constructor.
   *
   * @param oidcConfigurer the OIDC configurer
   */
  OidcFederationConfigurer(final @NonNull OidcProviderConfigurer oidcConfigurer) {
    this.oidcConfigurer = oidcConfigurer;
  }

  /**
   * Assigns whether the OpenID Provider is a member of an OpenID Federation. Defaults to {@code false}.
   *
   * @param enabled whether federation is enabled
   * @return this configurer
   */
  public @NonNull OidcFederationConfigurer enabled(final boolean enabled) {
    this.enabled = enabled;
    return this;
  }

  /**
   * Tells whether federation is enabled.
   *
   * @return {@code true} if federation is enabled and {@code false} otherwise
   */
  public boolean isEnabled() {
    return this.enabled;
  }

  /**
   * Assigns the authority hints: the entity identifiers of the immediate superiors of the OpenID Provider. At least one
   * is required.
   *
   * @param authorityHints the authority hints
   * @return this configurer
   */
  public @NonNull OidcFederationConfigurer authorityHints(final @Nullable List<String> authorityHints) {
    this.authorityHints = authorityHints;
    return this;
  }

  /**
   * Assigns the federation keys. They are separate from the OpenID Connect keys. All keys are published, and the first
   * active key signs. At least one active key is required.
   *
   * @param keys the federation keys
   * @return this configurer
   */
  public @NonNull OidcFederationConfigurer keys(final @Nullable List<FederationKey> keys) {
    this.keys = keys;
    return this;
  }

  /**
   * Assigns the lifetime of the entity configuration. Defaults to {@link #DEFAULT_ENTITY_CONFIGURATION_LIFETIME}.
   *
   * @param lifetime the lifetime
   * @return this configurer
   */
  public @NonNull OidcFederationConfigurer entityConfigurationLifetime(final @NonNull Duration lifetime) {
    this.entityConfigurationLifetime = Objects.requireNonNull(lifetime, "lifetime must not be null");
    return this;
  }

  /**
   * Assigns parameters that are applied to the entity configuration, for example {@code trust_anchor_hints}. A
   * {@code metadata} parameter, holding a map of entity types, is merged into the metadata per entity type and
   * parameter. Any other parameter is set as a claim. A change that concerns only the OpenID Provider metadata belongs
   * in the discovery document, so that both documents get it.
   *
   * @param additionalParameters the parameters, or {@code null}
   * @return this configurer
   */
  public @NonNull OidcFederationConfigurer additionalParameters(
      final @Nullable Map<String, Object> additionalParameters) {
    this.additionalParameters = additionalParameters;
    return this;
  }

  /**
   * Assigns a customizer that gets the claims of the entity configuration last, before it is signed, as a mutable map
   * where {@code metadata} and its entity types are mutable maps too. It may change anything except {@code iss},
   * {@code sub}, {@code iat} and {@code exp}. It runs each time the entity configuration is built.
   *
   * @param customizer the customizer
   * @return this configurer
   */
  public @NonNull OidcFederationConfigurer entityConfigurationCustomizer(
      final @NonNull Customizer<Map<String, Object>> customizer) {
    this.entityConfigurationCustomizer = Objects.requireNonNull(customizer, "customizer must not be null");
    return this;
  }

  /**
   * Assigns where the trust marks of the OpenID Provider are fetched, one source per trust mark type.
   *
   * @param trustMarks the trust mark sources, or {@code null}
   * @return this configurer
   */
  public @NonNull OidcFederationConfigurer trustMarks(final @Nullable List<TrustMarkSource> trustMarks) {
    this.trustMarks = trustMarks;
    return this;
  }

  /**
   * Assigns the directory where fetched trust marks are stored, so that they are available after a restart. Without a
   * directory, nothing is stored.
   *
   * @param directory the directory, or {@code null}
   * @return this configurer
   */
  public @NonNull OidcFederationConfigurer trustMarkCacheDirectory(final @Nullable Path directory) {
    this.trustMarkCacheDirectory = directory;
    return this;
  }

  /**
   * Assigns the interval between two attempts to fetch a trust mark after a failure. Defaults to
   * {@link ProviderTrustMarks#DEFAULT_RETRY_INTERVAL}.
   *
   * @param retryInterval the interval
   * @return this configurer
   */
  public @NonNull OidcFederationConfigurer trustMarkRetryInterval(final @NonNull Duration retryInterval) {
    this.trustMarkRetryInterval = Objects.requireNonNull(retryInterval, "retryInterval must not be null");
    return this;
  }

  /**
   * Assigns the object that keeps the trust marks of the OpenID Provider. When assigned, it replaces the one that is
   * otherwise created from the trust mark sources, the cache directory and the retry interval. Its entity identifier
   * must be the issuer.
   *
   * @param providerTrustMarks the trust marks, or {@code null}
   * @return this configurer
   */
  public @NonNull OidcFederationConfigurer providerTrustMarks(final @Nullable ProviderTrustMarks providerTrustMarks) {
    this.providerTrustMarks = providerTrustMarks;
    return this;
  }

  /**
   * Assigns the client that makes the federation calls. Defaults to an {@link HttpFederationClient}.
   *
   * @param federationClient the client, or {@code null} for the default
   * @return this configurer
   */
  public @NonNull OidcFederationConfigurer federationClient(final @Nullable FederationClient federationClient) {
    this.federationClient = federationClient;
    return this;
  }

  /**
   * Gets the federation keys. Available after initialization when federation is enabled.
   *
   * @return the federation keys
   */
  public @NonNull FederationKeys getFederationKeys() {
    return Objects.requireNonNull(this.federationKeys, "The configurer has not been initialized");
  }

  /**
   * Gets the trust marks of the OpenID Provider, and the state of each trust mark type. Available after the configurer
   * has been applied when federation is enabled.
   *
   * @return the trust marks
   */
  public @NonNull ProviderTrustMarks getProviderTrustMarks() {
    return Objects.requireNonNull(this.activeTrustMarks, "The configurer has not been applied");
  }

  /**
   * Gets the container holding the entity configuration. Available after the configurer has been applied when
   * federation is enabled.
   *
   * @return the container
   */
  public @NonNull EntityConfigurationContainer getEntityConfigurationContainer() {
    return Objects.requireNonNull(this.container, "The configurer has not been applied");
  }

  /**
   * Gets the path of the entity configuration endpoint relative to the application: the part of the issuer after the
   * base URL, followed by {@value #WELL_KNOWN_PATH}.
   *
   * @return the path
   */
  public @NonNull String getEndpointPath() {
    final String baseUrl = Objects.requireNonNull(this.oidcConfigurer.getServer().getBaseUrl());
    return this.oidcConfigurer.getIssuer().substring(baseUrl.length()) + WELL_KNOWN_PATH;
  }

  /**
   * Initializes the configurer: checks the settings and creates the keys.
   *
   * @throws IllegalArgumentException if federation is enabled and a setting is missing or invalid
   */
  void init() {
    if (!this.enabled) {
      return;
    }
    if (this.keys == null || this.keys.isEmpty()) {
      throw new IllegalArgumentException("OpenID Federation is enabled for the OpenID Provider, but no federation "
          + "keys are configured (authn-server.oidc.federation.keys)");
    }
    if (this.authorityHints == null || this.authorityHints.isEmpty()) {
      throw new IllegalArgumentException("OpenID Federation is enabled for the OpenID Provider, but no authority "
          + "hints are configured (authn-server.oidc.federation.authority-hints)");
    }
    if (this.entityConfigurationLifetime.isZero() || this.entityConfigurationLifetime.isNegative()) {
      throw new IllegalArgumentException("The entity configuration lifetime must be positive");
    }
    this.federationKeys = new FederationKeys(this.keys);
    this.oidcConfigurer.getEntityMetadata().validate();
    this.requestMatcher = PathPatternRequestMatcher.pathPattern(HttpMethod.GET, this.getEndpointPath());
  }

  /**
   * Gets the request matcher for the entity configuration endpoint.
   *
   * @return the request matcher, or {@code null} if federation is not enabled
   */
  @Nullable RequestMatcher getRequestMatcher() {
    return this.requestMatcher;
  }

  /**
   * Starts the trust mark job, builds the entity configuration and adds the filter that publishes it.
   *
   * @param http the HTTP security object
   * @param providerMetadata the discovery document as JSON
   * @throws IllegalArgumentException if the entity configuration cannot be built
   */
  void configure(final @NonNull HttpSecurity http, final @NonNull Map<String, Object> providerMetadata) {
    if (!this.enabled) {
      return;
    }
    final String entityId = this.oidcConfigurer.getIssuer();
    if (this.providerTrustMarks != null) {
      if (!entityId.equals(this.providerTrustMarks.getEntityId())) {
        throw new IllegalArgumentException("The provider trust marks are for '%s', not for the issuer '%s'"
            .formatted(this.providerTrustMarks.getEntityId(), entityId));
      }
      this.activeTrustMarks = this.providerTrustMarks;
    }
    else {
      this.activeTrustMarks = new ProviderTrustMarks(entityId,
          this.trustMarks != null ? this.trustMarks : List.of(),
          this.federationClient != null ? this.federationClient : new HttpFederationClient(),
          this.trustMarkCacheDirectory, this.trustMarkRetryInterval, Clock.systemUTC());
    }
    if (http.getSharedObject(ApplicationContext.class) instanceof final ApplicationContext context) {
      this.activeTrustMarks.setEventPublisher(context);
    }
    this.activeTrustMarks.start();

    final Map<String, Object> metadata = new LinkedHashMap<>(providerMetadata);
    this.oidcConfigurer.getEntityMetadata().toParameters().forEach(metadata::putIfAbsent);
    metadata.putIfAbsent(CLIENT_REGISTRATION_TYPES_SUPPORTED, List.of("automatic"));

    final FederationKeys keys = this.federationKeys;
    final EntityConfigurationBuilder builder = new EntityConfigurationBuilder(entityId, this.authorityHints,
        () -> keys, this.activeTrustMarks::getTrustMarks, metadata, this.entityConfigurationLifetime);
    builder.setAdditionalParameters(this.additionalParameters);
    builder.setCustomizer(this.entityConfigurationCustomizer);
    this.container = new EntityConfigurationContainer(builder);
    try {
      this.container.getEntityConfiguration();
    }
    catch (final IllegalStateException e) {
      throw new IllegalArgumentException(e.getMessage(), e);
    }

    http.addFilterBefore(this.oidcConfigurer.postProcessObject(
        new OidcEntityConfigurationEndpointFilter(this.container, Objects.requireNonNull(this.requestMatcher))),
        AbstractPreAuthenticatedProcessingFilter.class);

    log.info("OpenID Federation entity configuration of '{}' - authority hints: {}, federation keys: {}, "
        + "trust marks: {}", entityId, this.authorityHints, this.federationKeys,
        this.activeTrustMarks.getStates().stream().map(TrustMarkState::trustMarkType).toList());
  }

}
