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
package se.swedenconnect.spring.authnserver.autoconfigure.oidc;

import java.io.IOException;
import java.io.InputStream;
import java.text.ParseException;
import java.time.Clock;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.core.io.Resource;
import org.springframework.util.StringUtils;

import com.nimbusds.jose.jwk.JWKSet;

import se.swedenconnect.oidf.common.entity.entity.integration.federation.FederationClient;
import se.swedenconnect.spring.authnserver.config.AuthnServerConfigurer;
import se.swedenconnect.spring.authnserver.oidc.client.federation.EntityConfigurationEndpoints;
import se.swedenconnect.spring.authnserver.oidc.client.federation.FederationCache;
import se.swedenconnect.spring.authnserver.oidc.client.federation.FederationCacheRefresher;
import se.swedenconnect.spring.authnserver.oidc.client.federation.FederationCacheSettings;
import se.swedenconnect.spring.authnserver.oidc.client.federation.FederationClientBackend;
import se.swedenconnect.spring.authnserver.oidc.client.federation.FederationSettings;
import se.swedenconnect.spring.authnserver.oidc.client.federation.HttpFederationResolver;
import se.swedenconnect.spring.authnserver.oidc.client.federation.HttpTrustMarkRequester;
import se.swedenconnect.spring.authnserver.oidc.client.federation.TrustMarkStatusChecker;

/**
 * The client source that resolves OpenID Connect clients through OpenID Federation, set up from
 * {@code authn-server.oidc.federation.trust-anchor} and {@code authn-server.oidc.federation.clients}.
 * <p>
 * The source is a {@link FederationClientBackend} named {@value #NAME}. It is added to the client registry after every
 * {@link se.swedenconnect.spring.authnserver.config.AuthnServerConfigurerAdapter AuthnServerConfigurerAdapter} has run,
 * so it is asked after the configured clients and after any client source added in code. It is not added when the
 * client source is turned off, when an adapter has added a {@link FederationClientBackend} of its own, or when the
 * application assigns a client registry of its own.
 * </p>
 * <p>
 * Endpoints that are not configured are found in the entity configurations of the resolver and the trust mark issuers
 * when they are first needed, see {@link EntityConfigurationEndpoints}. Nothing is fetched at startup, so a federation
 * that cannot be reached never stops the OpenID Provider. The background jobs, the cache refresh and the trust mark
 * status checks, are started with the source and stopped with the application context.
 * </p>
 *
 * @author Martin Lindström
 */
public class OidcFederationClientSource implements DisposableBean {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(OidcFederationClientSource.class);

  /** The name of the client source. */
  public static final String NAME = FederationClientBackend.DEFAULT_NAME;

  /** The prefix of the federation properties. */
  private static final String FEDERATION = OidcConfigurationProperties.PREFIX + ".federation";

  /** The federation properties. */
  private final OidcConfigurationProperties.FederationProperties properties;

  /** Where resolved clients are kept. */
  private final FederationCache cache;

  /** The client making the federation calls. */
  private final FederationClient federationClient;

  /** Publishes the failures to find an endpoint and the trust mark alerts, or {@code null}. */
  private final ApplicationEventPublisher eventPublisher;

  /** The source, or {@code null} until it has been added. */
  private FederationClientBackend backend;

  /** The cache refresh job, or {@code null}. */
  private FederationCacheRefresher refresher;

  /** The trust mark status job, or {@code null}. */
  private TrustMarkStatusChecker statusChecker;

  /**
   * Constructor.
   *
   * @param properties the federation properties
   * @param cache where resolved clients are kept
   * @param federationClient the client making the federation calls
   * @param eventPublisher publishes the failures to find an endpoint and the trust mark alerts, or {@code null}
   */
  public OidcFederationClientSource(final OidcConfigurationProperties.@NonNull FederationProperties properties,
      final @NonNull FederationCache cache, final @NonNull FederationClient federationClient,
      final @Nullable ApplicationEventPublisher eventPublisher) {
    this.properties = Objects.requireNonNull(properties, "properties must not be null");
    this.cache = Objects.requireNonNull(cache, "cache must not be null");
    this.federationClient = Objects.requireNonNull(federationClient, "federationClient must not be null");
    this.eventPublisher = eventPublisher;
  }

  /**
   * Adds the client source to the server, unless it is turned off, an adapter has added a
   * {@link FederationClientBackend} of its own, or a client registry has been assigned.
   *
   * @param server the shared configurer
   * @return the added source, or {@code null} if none was added
   * @throws IllegalArgumentException if the properties are incomplete or invalid
   * @throws IOException if a JWK Set cannot be read
   */
  public synchronized @Nullable FederationClientBackend addTo(final @NonNull AuthnServerConfigurer server)
      throws IOException {
    if (!this.properties.getClients().isEnabled()) {
      log.debug("Resolving clients through the federation is turned off");
      return null;
    }
    if (server.isClientRegistryAssigned()) {
      log.info("A client registry is assigned - {}.clients is not used", FEDERATION);
      return null;
    }
    if (server.getClientRegistryBackends().stream().anyMatch(FederationClientBackend.class::isInstance)) {
      log.info("A federation client source has been added in code - {}.clients is not used", FEDERATION);
      return null;
    }
    if (this.backend != null) {
      server.clientRegistryBackend(this.backend);
      return this.backend;
    }

    final FederationSettings settings = createSettings(this.properties);
    final EntityConfigurationEndpoints endpoints = new EntityConfigurationEndpoints(this.federationClient);
    endpoints.setEventPublisher(this.eventPublisher);

    final FederationClientBackend source = new FederationClientBackend(
        new HttpFederationResolver(settings, this.federationClient, endpoints),
        new HttpTrustMarkRequester(settings, this.federationClient, endpoints),
        this.cache, createCacheSettings(this.properties.getClients().getCache()));
    source.setName(NAME);
    server.clientRegistryBackend(source);
    this.backend = source;

    this.refresher = new FederationCacheRefresher(source);
    this.refresher.start();
    if (!settings.trustMarkIssuers().isEmpty()) {
      this.statusChecker = new TrustMarkStatusChecker(this.cache, settings, this.federationClient, endpoints,
          Optional.ofNullable(this.properties.getClients().getTrustMarkStatusInterval())
              .orElse(TrustMarkStatusChecker.DEFAULT_INTERVAL),
          Clock.systemUTC());
      this.statusChecker.setEventPublisher(this.eventPublisher);
      this.statusChecker.start();
    }
    log.info("Clients are resolved through the federation of the trust anchor {}, by the resolver {}",
        settings.trustAnchor().entityId(), settings.resolver().entityId());
    return source;
  }

  /**
   * Gets the client source.
   *
   * @return the source, or {@code null} if it has not been added
   */
  public synchronized @Nullable FederationClientBackend getBackend() {
    return this.backend;
  }

  /**
   * Stops the background jobs.
   */
  @Override
  public synchronized void destroy() {
    if (this.refresher != null) {
      this.refresher.close();
    }
    if (this.statusChecker != null) {
      this.statusChecker.close();
    }
  }

  /**
   * Creates the federation settings from the properties.
   *
   * @param properties the federation properties
   * @return the settings
   * @throws IllegalArgumentException if the properties are incomplete or invalid
   * @throws IOException if a JWK Set cannot be read
   */
  static @NonNull FederationSettings createSettings(
      final OidcConfigurationProperties.@NonNull FederationProperties properties) throws IOException {

    final OidcConfigurationProperties.TrustAnchorProperties trustAnchor = properties.getTrustAnchor();
    if (!StringUtils.hasText(trustAnchor.getEntityId()) || trustAnchor.getJwks() == null) {
      throw new IllegalArgumentException(("Missing trust anchor - assign %1$s.trust-anchor.entity-id and "
          + "%1$s.trust-anchor.jwks, or turn off resolving clients through the federation with "
          + "%1$s.clients.enabled=false").formatted(FEDERATION));
    }
    final String trustAnchorId = trustAnchor.getEntityId().trim();
    final FederationSettings.TrustAnchor anchor = new FederationSettings.TrustAnchor(trustAnchorId,
        loadJwks(trustAnchor.getJwks(), FEDERATION + ".trust-anchor.jwks"));

    final OidcConfigurationProperties.ResolverProperties resolver = properties.getClients().getResolver();
    final String resolverId = StringUtils.hasText(resolver.getEntityId()) ? resolver.getEntityId().trim()
        : trustAnchorId;
    final JWKSet resolverKeys;
    if (resolverId.equals(trustAnchorId)) {
      resolverKeys = null;
    }
    else if (resolver.getJwks() == null) {
      throw new IllegalArgumentException(
          "Missing %s.clients.resolver.jwks - the keys of the resolver %s must be given since it is not the trust anchor"
              .formatted(FEDERATION, resolverId));
    }
    else {
      resolverKeys = loadJwks(resolver.getJwks(), FEDERATION + ".clients.resolver.jwks");
    }

    final Map<String, FederationSettings.TrustMarkIssuer> issuers = new LinkedHashMap<>();
    final List<OidcConfigurationProperties.TrustMarkIssuerProperties> issuerProperties =
        Optional.ofNullable(properties.getClients().getTrustMarkIssuers()).orElse(List.of());
    for (int i = 0; i < issuerProperties.size(); i++) {
      final OidcConfigurationProperties.TrustMarkIssuerProperties p = issuerProperties.get(i);
      final String name = "%s.clients.trust-mark-issuers[%d]".formatted(FEDERATION, i);
      if (!StringUtils.hasText(p.getType()) || !StringUtils.hasText(p.getIssuer())) {
        throw new IllegalArgumentException("%s must have type and issuer".formatted(name));
      }
      final String issuerId = p.getIssuer().trim();
      final JWKSet keys;
      if (issuerId.equals(trustAnchorId)) {
        keys = null;
      }
      else if (p.getJwks() == null) {
        throw new IllegalArgumentException(
            "Missing %s.jwks - the keys of the trust mark issuer %s must be given since it is not the trust anchor"
                .formatted(name, issuerId));
      }
      else {
        keys = loadJwks(p.getJwks(), name + ".jwks");
      }
      if (issuers.put(p.getType().trim(), new FederationSettings.TrustMarkIssuer(issuerId, p.getEndpoint(), keys,
          p.getStatusEndpoint())) != null) {
        throw new IllegalArgumentException(
            "The trust mark type '%s' has more than one issuer under %s.clients.trust-mark-issuers"
                .formatted(p.getType(), FEDERATION));
      }
    }
    return new FederationSettings(anchor,
        new FederationSettings.Resolver(resolverId, resolver.getEndpoint(), resolverKeys), issuers);
  }

  /**
   * Creates the cache settings from the properties, with the defaults of {@link FederationCacheSettings} for values
   * that are not assigned.
   *
   * @param properties the cache properties
   * @return the cache settings
   */
  static @NonNull FederationCacheSettings createCacheSettings(
      final OidcConfigurationProperties.@NonNull FederationCacheProperties properties) {
    final OidcConfigurationProperties.FederationCacheRefreshProperties refresh = properties.getRefresh();
    final FederationCacheSettings.RefreshSettings defaults =
        FederationCacheSettings.RefreshSettings.enabled(refresh.isEnabled());
    return new FederationCacheSettings(
        properties.getMaximumAge(),
        Optional.ofNullable(properties.getNotFoundTimeToLive())
            .orElse(FederationCacheSettings.DEFAULT_NOT_FOUND_TIME_TO_LIVE),
        new FederationCacheSettings.RefreshSettings(
            defaults.enabled(),
            Optional.ofNullable(refresh.getInterval()).orElse(defaults.interval()),
            Optional.ofNullable(refresh.getRefreshAhead()).orElse(defaults.refreshAhead()),
            Optional.ofNullable(refresh.getMinimumLookups()).orElse(defaults.minimumLookups()),
            Optional.ofNullable(refresh.getLookupPeriod()).orElse(defaults.lookupPeriod()),
            Optional.ofNullable(refresh.getMaximumClients()).orElse(defaults.maximumClients()),
            Optional.ofNullable(refresh.getMaximumTrackedClients()).orElse(defaults.maximumTrackedClients())));
  }

  /**
   * Reads a JWK Set document.
   *
   * @param location the location of the document
   * @param name the name of the property, for error messages
   * @return the JWK Set
   * @throws IllegalArgumentException if the document is not a valid JWK Set, or holds no keys
   * @throws IOException if the document cannot be read
   */
  static @NonNull JWKSet loadJwks(final @NonNull Resource location, final @NonNull String name) throws IOException {
    final JWKSet keys;
    try (final InputStream is = location.getInputStream()) {
      keys = JWKSet.load(is);
    }
    catch (final ParseException e) {
      throw new IllegalArgumentException("%s is not a valid JWK Set - %s".formatted(name, e.getMessage()), e);
    }
    if (keys.getKeys().isEmpty()) {
      throw new IllegalArgumentException("%s holds no keys".formatted(name));
    }
    return keys;
  }

}
