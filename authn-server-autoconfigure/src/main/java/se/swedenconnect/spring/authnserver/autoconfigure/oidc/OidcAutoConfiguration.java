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
import java.nio.file.Path;
import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;

import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.config.properties.PkiCredentialConfigurationProperties;
import se.swedenconnect.security.credential.factory.PkiCredentialFactory;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.autoconfigure.AuthnServerConfigurationProperties;
import se.swedenconnect.spring.authnserver.autoconfigure.AuthnServerProtocolConfigurerFactory;
import se.swedenconnect.spring.authnserver.config.AuthnServerConfigurer;
import se.swedenconnect.spring.authnserver.entity.EntityInformation;
import se.swedenconnect.spring.authnserver.oidc.attributes.OidcAttributeMapping;
import se.swedenconnect.oidf.common.entity.entity.integration.federation.FederationClient;
import se.swedenconnect.spring.authnserver.oidc.client.ConfigurationClientBackend;
import se.swedenconnect.spring.authnserver.oidc.client.OidcClientReader;
import se.swedenconnect.spring.authnserver.oidc.client.OidcClientRecord;
import se.swedenconnect.spring.authnserver.oidc.client.federation.HttpFederationClient;
import se.swedenconnect.spring.authnserver.oidc.config.OidcProviderConfigurer;
import se.swedenconnect.spring.authnserver.oidc.federation.InMemoryProviderTrustMarkStore;
import se.swedenconnect.spring.authnserver.oidc.federation.ProviderTrustMarkStore;
import se.swedenconnect.spring.authnserver.oidc.federation.ProviderTrustMarks;
import se.swedenconnect.spring.authnserver.oidc.federation.TrustMarkSource;
import se.swedenconnect.spring.authnserver.oidc.keys.DecryptionKey;
import se.swedenconnect.spring.authnserver.oidc.keys.FederationKey;
import se.swedenconnect.spring.authnserver.oidc.keys.SigningKey;
import se.swedenconnect.spring.authnserver.oidc.scope.ScopeRegistry;
import se.swedenconnect.spring.authnserver.oidc.subject.SubjectGeneratorFactory;
import se.swedenconnect.spring.authnserver.oidc.token.AccessTokenStore;
import se.swedenconnect.spring.authnserver.oidc.token.AuthorizationCodeStore;
import se.swedenconnect.spring.authnserver.oidc.token.ClientAssertionReplayCache;
import se.swedenconnect.spring.authnserver.registry.acceptance.ConfigurableRequesterAcceptance;
import se.swedenconnect.spring.authnserver.registry.acceptance.RequiredMarksRequesterPredicate;
import se.swedenconnect.spring.authnserver.registry.acceptance.WhitelistRequesterPredicate;

/**
 * Autoconfiguration for the OpenID Provider. Active when the OIDC module is on the classpath and
 * {@code authn-server.oidc.enabled} is {@code true}.
 * <p>
 * It declares the factory that creates the {@link OidcProviderConfigurer} from the
 * {@link OidcConfigurationProperties}, loading the keys through the credentials-support library. The requester
 * acceptance rules of the properties are added to the server's {@link ConfigurableRequesterAcceptance}. A
 * {@link ScopeRegistry}, an {@link OidcAttributeMapping} or a {@link SubjectGeneratorFactory} bean replaces the
 * default one.
 * </p>
 * <p>
 * An {@link AuthorizationCodeStore}, an {@link AccessTokenStore} or a {@link ClientAssertionReplayCache} bean replaces
 * the in-memory store. When a store is kept in Redis, the bean is declared by the storage autoconfiguration.
 * </p>
 * <p>
 * The clients of {@code authn-server.oidc.clients} are read at startup into a {@link ConfigurationClientBackend}
 * named {@value #CLIENTS_SOURCE_NAME}, which is asked before any client source that an adapter adds.
 * </p>
 * <p>
 * When OpenID Federation is enabled, the trust marks of the OpenID Provider are kept by a {@link ProviderTrustMarks}
 * bean, created from the properties unless the application declares one. A {@link ProviderTrustMarkStore} bean decides
 * where their state is kept.
 * </p>
 * <p>
 * An {@link HttpFederationClient} bean makes the federation calls, unless the application declares a
 * {@link FederationClient}. As a bean it publishes the outcome of every call, which the health of the federation
 * services is built from, so an application that sets up the federation backend of the client registry should use it.
 * </p>
 *
 * @author Martin Lindström
 */
@AutoConfiguration(afterName = "se.swedenconnect.security.credential.spring.autoconfigure."
    + "SpringCredentialBundlesAutoConfiguration")
@ConditionalOnClass(OidcProviderConfigurer.class)
@ConditionalOnProperty(prefix = OidcConfigurationProperties.PREFIX, name = "enabled", havingValue = "true")
@EnableConfigurationProperties(OidcConfigurationProperties.class)
public class OidcAutoConfiguration {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(OidcAutoConfiguration.class);

  /** The name of the client source holding the clients of {@code authn-server.oidc.clients}. */
  public static final String CLIENTS_SOURCE_NAME = "properties";

  /**
   * Creates the factory for the OIDC protocol configurer.
   *
   * @param properties the OIDC properties
   * @param credentialFactory the credential factory, for loading the keys
   * @param scopeRegistry a scope registry, if declared as a bean
   * @param attributeMapping an attribute mapping, if declared as a bean
   * @param subjectGeneratorFactory a subject generator factory, if declared as a bean
   * @param providerTrustMarks the trust marks of the OpenID Provider, when federation is enabled
   * @param authorizationCodeStore an authorization code store, if declared as a bean
   * @param accessTokenStore an access token store, if declared as a bean
   * @param clientAssertionReplayCache a cache of used client assertions, if declared as a bean
   * @return an {@link AuthnServerProtocolConfigurerFactory}
   */
  @Bean
  AuthnServerProtocolConfigurerFactory oidcProtocolConfigurerFactory(
      final OidcConfigurationProperties properties,
      final PkiCredentialFactory credentialFactory,
      final ObjectProvider<ScopeRegistry> scopeRegistry,
      final ObjectProvider<OidcAttributeMapping> attributeMapping,
      final ObjectProvider<SubjectGeneratorFactory> subjectGeneratorFactory,
      final ObjectProvider<ProviderTrustMarks> providerTrustMarks,
      final ObjectProvider<AuthorizationCodeStore> authorizationCodeStore,
      final ObjectProvider<AccessTokenStore> accessTokenStore,
      final ObjectProvider<ClientAssertionReplayCache> clientAssertionReplayCache) {

    return server -> {
      final List<FederationKey> federationKeys =
          loadFederationKeys(properties.getFederation().getKeys(), credentialFactory);
      final ConfigurationClientBackend clients = createClientBackend(properties.getClients());
      if (clients != null) {
        server.clientRegistryBackend(clients);
      }
      return createConfigurer(server, properties)
          .signingKeys(loadSigningKeys(properties.getKeys().getSigning(), credentialFactory))
          .decryptionKeys(loadDecryptionKeys(properties.getKeys().getDecryption(), credentialFactory))
          .scopeRegistry(scopeRegistry.getIfUnique())
          .attributeMapping(attributeMapping.getIfUnique())
          .subjectGeneratorFactory(subjectGeneratorFactory.getIfUnique())
          .authnRequestProcessor(c -> c
              .authorizationCodeStore(authorizationCodeStore.getIfUnique())
              .accessTokenStore(accessTokenStore.getIfUnique())
              .clientAssertionReplayCache(clientAssertionReplayCache.getIfUnique()))
          .federation(f -> f
              .keys(federationKeys)
              .providerTrustMarks(providerTrustMarks.getIfUnique()));
    };
  }

  /**
   * Creates the client that makes the federation calls. As a bean it publishes the outcome of every call.
   *
   * @return an {@link HttpFederationClient}
   */
  @Bean
  @ConditionalOnMissingBean(FederationClient.class)
  HttpFederationClient oidcFederationClient() {
    return new HttpFederationClient();
  }

  /**
   * Creates the object that keeps the trust marks of the OpenID Provider, when OpenID Federation is enabled. It is a
   * bean so that the state of the trust marks can be read, for example by a health check.
   * <p>
   * In memory, the trust marks are kept in {@code authn-server.oidc.federation.trust-mark-cache-directory}, or else
   * in the directory {@value AuthnServerConfigurationProperties#OIDC_TRUST_MARKS_DIRECTORY} of
   * {@code authn-server.cache-directory}.
   * </p>
   *
   * @param properties the OIDC properties
   * @param shared the shared properties, giving the base URL and the cache directory
   * @param store where the trust marks are kept, if declared as a bean
   * @param federationClient the client making the calls, if declared as a bean
   * @return a {@link ProviderTrustMarks}
   * @throws IOException if the keys of a trust mark issuer cannot be read
   */
  @Bean
  @ConditionalOnMissingBean
  @ConditionalOnProperty(prefix = OidcConfigurationProperties.PREFIX + ".federation", name = "enabled",
      havingValue = "true")
  ProviderTrustMarks oidcProviderTrustMarks(final OidcConfigurationProperties properties,
      final AuthnServerConfigurationProperties shared, final ObjectProvider<ProviderTrustMarkStore> store,
      final ObjectProvider<FederationClient> federationClient)
      throws IOException {
    final String entityId = properties.getIssuer() != null ? properties.getIssuer() : shared.getBaseUrl();
    if (entityId == null) {
      throw new IllegalArgumentException("Missing base URL - assign " + AuthnServerConfigurationProperties.PREFIX
          + ".base-url");
    }
    final OidcConfigurationProperties.FederationProperties federation = properties.getFederation();
    final Duration retryInterval =
        Optional.ofNullable(federation.getTrustMarkRetryInterval()).orElse(ProviderTrustMarks.DEFAULT_RETRY_INTERVAL);
    final ProviderTrustMarkStore trustMarkStore = store.getIfUnique();
    final FederationClient client = federationClient.getIfUnique(HttpFederationClient::new);
    if (trustMarkStore == null || trustMarkStore instanceof InMemoryProviderTrustMarkStore) {
      final Path cacheDirectory = federation.getTrustMarkCacheDirectory() != null
          ? federation.getTrustMarkCacheDirectory().toPath()
          : shared.getCachePath(AuthnServerConfigurationProperties.OIDC_TRUST_MARKS_DIRECTORY);
      return new ProviderTrustMarks(entityId, loadTrustMarkSources(federation.getTrustMarks()),
          Objects.requireNonNullElseGet(trustMarkStore, InMemoryProviderTrustMarkStore::new), client,
          cacheDirectory, retryInterval, Clock.systemUTC());
    }
    if (federation.getTrustMarkCacheDirectory() != null) {
      log.info("The trust marks are kept in a shared store - {}.federation.trust-mark-cache-directory is not used",
          OidcConfigurationProperties.PREFIX);
    }
    return new ProviderTrustMarks(entityId, loadTrustMarkSources(federation.getTrustMarks()), trustMarkStore,
        client, null, retryInterval, Clock.systemUTC());
  }

  /**
   * Creates the client source holding the clients of {@code authn-server.oidc.clients}, named
   * {@value #CLIENTS_SOURCE_NAME}.
   *
   * @param properties the client entries
   * @return the client source, or {@code null} if no entries are assigned
   * @throws IllegalArgumentException for an invalid entry or client
   */
  static @Nullable ConfigurationClientBackend createClientBackend(
      final @Nullable List<OidcConfigurationProperties.ClientProperties> properties) {
    if (properties == null || properties.isEmpty()) {
      return null;
    }
    final OidcClientReader reader = new OidcClientReader();
    for (int i = 0; i < properties.size(); i++) {
      final OidcConfigurationProperties.ClientProperties p = properties.get(i);
      final String name = "%s.clients[%d]".formatted(OidcConfigurationProperties.PREFIX, i);
      if (p.getLocation() != null && p.hasInlineFields()) {
        throw new IllegalArgumentException(
            "%s has both a location and inline fields - give either a location or an inline client".formatted(name));
      }
      if (p.getLocation() != null) {
        reader.readLocation(p.getLocation());
      }
      else if (p.hasInlineFields()) {
        if (p.getClientId() == null || p.getMetadata() == null) {
          throw new IllegalArgumentException("%s must have client-id and metadata".formatted(name));
        }
        reader.addClient(p.getClientId(), p.getMetadata(), p.getClientSecret(), p.getTrustMarkTypes(), name);
      }
      else {
        throw new IllegalArgumentException(
            "%s has neither a location nor an inline client (client-id and metadata)".formatted(name));
      }
    }
    final List<OidcClientRecord> clients = reader.getClients();
    log.info("Configured {} OpenID Connect client(s) from {}.clients", clients.size(),
        OidcConfigurationProperties.PREFIX);
    return new ConfigurationClientBackend(clients, CLIENTS_SOURCE_NAME);
  }

  /**
   * Creates an {@link OidcProviderConfigurer} from the property values, except the keys. Values that have not been
   * assigned are left at the configurer's defaults.
   *
   * @param server the shared configurer
   * @param properties the OIDC properties
   * @return the configurer
   */
  static @NonNull OidcProviderConfigurer createConfigurer(final @NonNull AuthnServerConfigurer server,
      final @NonNull OidcConfigurationProperties properties) {

    final OidcProviderConfigurer configurer = new OidcProviderConfigurer();
    if (properties.getPath() != null) {
      configurer.path(properties.getPath());
    }
    configurer.issuer(properties.getIssuer());
    if (properties.getSso().isAssigned()) {
      configurer.ssoPolicy(
          properties.getSso().toPolicy(server.getSsoPolicy(), OidcConfigurationProperties.PREFIX + ".sso"));
    }
    configurer.clockSkew(properties.getClockSkew());
    configurer.supportsUserMessage(properties.getSupportsUserMessage());
    configurer.subjectIdentifierSecret(properties.getSubjectIdentifier().getSecretBytes());
    configurer.subjectIdentifierHashAlgorithm(properties.getSubjectIdentifier().getHashAlgorithm());

    if (properties.getEndpoints().getJwks() != null) {
      configurer.jwksEndpoint(properties.getEndpoints().getJwks());
    }
    if (properties.getEndpoints().getAuthorization() != null) {
      configurer.authorizationEndpoint(properties.getEndpoints().getAuthorization());
    }
    if (properties.getEndpoints().getToken() != null) {
      configurer.tokenEndpoint(properties.getEndpoints().getToken());
    }
    if (properties.getEndpoints().getUserinfo() != null) {
      configurer.userInfoEndpoint(properties.getEndpoints().getUserinfo());
    }
    final OidcConfigurationProperties.TokenProperties tokens = properties.getTokens();
    if (tokens.getAuthorizationCodeLifetime() != null) {
      configurer.authorizationCodeLifetime(tokens.getAuthorizationCodeLifetime());
    }
    if (tokens.getAccessTokenLifetime() != null) {
      configurer.accessTokenLifetime(tokens.getAccessTokenLifetime());
    }
    if (tokens.getAccessTokenSingleUse() != null) {
      configurer.singleUseAccessTokens(tokens.getAccessTokenSingleUse());
    }
    if (tokens.getIdTokenLifetime() != null) {
      configurer.idTokenLifetime(tokens.getIdTokenLifetime());
    }
    if (properties.getClientAuthenticationMethods() != null) {
      configurer.clientAuthenticationMethods(properties.getClientAuthenticationMethods().stream()
          .map(String::trim)
          .map(ClientAuthenticationMethod::parse)
          .collect(Collectors.toSet()));
    }
    final OidcConfigurationProperties.AuthorizationRequestProperties authorizationRequest =
        properties.getAuthorizationRequest();
    if (authorizationRequest.getRequirePkce() != null) {
      configurer.requirePkce(authorizationRequest.getRequirePkce());
    }
    if (authorizationRequest.getRequireSignedRequestObject() != null) {
      configurer.requireSignedRequestObject(authorizationRequest.getRequireSignedRequestObject());
    }
    if (authorizationRequest.getRequireState() != null) {
      configurer.requireState(authorizationRequest.getRequireState());
    }
    if (properties.getSignUserInfo() != null) {
      configurer.signUserInfo(properties.getSignUserInfo());
    }
    configurer.scopes(properties.getScopes());
    configurer.claims(properties.getClaims());
    configurer.uiLocales(properties.getUiLocales());

    final Map<String, Object> additionalParameters = properties.getDiscovery().getAdditionalParameters();
    if (additionalParameters != null) {
      final Map<String, Object> parameters = new LinkedHashMap<>();
      additionalParameters.forEach((name, value) -> parameters.put(name, toParameterValue(value)));
      configurer.discoveryEndpoint(d -> d.additionalParameters(parameters));
    }
    applyRequesterAcceptance(server, properties.getRequesterAcceptance());

    final EntityInformation information = properties.getEntityInformation().toEntityInformation();
    if (!information.isEmpty()) {
      configurer.entityInformation(information);
    }
    configurer.entityMetadata(properties.getEntityInformation().toEntityMetadata());

    final OidcConfigurationProperties.FederationProperties federation = properties.getFederation();
    configurer.federation(f -> {
      f.enabled(federation.isEnabled());
      f.authorityHints(federation.getAuthorityHints());
      if (federation.getEntityConfigurationLifetime() != null) {
        f.entityConfigurationLifetime(federation.getEntityConfigurationLifetime());
      }
      if (federation.getAdditionalParameters() != null) {
        final Map<String, Object> parameters = new LinkedHashMap<>();
        federation.getAdditionalParameters().forEach((name, value) -> parameters.put(name, toParameterValue(value)));
        f.additionalParameters(parameters);
      }
    });
    return configurer;
  }

  /**
   * Loads the federation keys.
   *
   * @param properties the key properties
   * @param credentialFactory the credential factory
   * @return the federation keys, or {@code null} if none are configured
   * @throws Exception for errors loading a credential
   */
  static @Nullable List<FederationKey> loadFederationKeys(
      final @Nullable List<OidcConfigurationProperties.FederationKeyProperties> properties,
      final @NonNull PkiCredentialFactory credentialFactory) throws Exception {
    if (properties == null) {
      return null;
    }
    final List<FederationKey> keys = new ArrayList<>();
    for (int i = 0; i < properties.size(); i++) {
      final OidcConfigurationProperties.FederationKeyProperties key = properties.get(i);
      if (key.getCredential() == null) {
        throw new IllegalArgumentException(
            "Missing credential for %s.federation.keys[%d]".formatted(OidcConfigurationProperties.PREFIX, i));
      }
      keys.add(new FederationKey(credentialFactory.createCredential(key.getCredential()), key.getState()));
    }
    return keys;
  }

  /**
   * Creates the trust mark sources of the properties, reading the keys of each issuer.
   *
   * @param properties the trust mark properties
   * @return the trust mark sources
   * @throws IOException if the keys of an issuer cannot be read
   */
  static @NonNull List<TrustMarkSource> loadTrustMarkSources(
      final @Nullable List<OidcConfigurationProperties.TrustMarkProperties> properties) throws IOException {
    if (properties == null) {
      return List.of();
    }
    final List<TrustMarkSource> sources = new ArrayList<>();
    for (int i = 0; i < properties.size(); i++) {
      final OidcConfigurationProperties.TrustMarkProperties p = properties.get(i);
      final String name = "%s.federation.trust-marks[%d]".formatted(OidcConfigurationProperties.PREFIX, i);
      if (p.getType() == null || p.getIssuer() == null || p.getEndpoint() == null || p.getJwks() == null) {
        throw new IllegalArgumentException("%s must have type, issuer, endpoint and jwks".formatted(name));
      }
      final JWKSet keys;
      try (final InputStream is = p.getJwks().getInputStream()) {
        keys = JWKSet.load(is);
      }
      catch (final ParseException e) {
        throw new IllegalArgumentException("%s.jwks is not a valid JWK Set - %s".formatted(name, e.getMessage()), e);
      }
      sources.add(new TrustMarkSource(p.getType(), p.getIssuer(), p.getEndpoint(), keys));
    }
    return sources;
  }

  /**
   * Adds the requester acceptance rules of the properties to the server's configurable requester acceptance. Nothing is
   * done when no rule is assigned.
   *
   * @param server the shared configurer
   * @param properties the requester acceptance properties
   */
  private static void applyRequesterAcceptance(final @NonNull AuthnServerConfigurer server,
      final OidcConfigurationProperties.@NonNull RequesterAcceptanceProperties properties) {

    final boolean hasWhitelist = properties.getWhitelist() != null && !properties.getWhitelist().isEmpty();
    final boolean hasMarks = properties.getRequiredMarks() != null && !properties.getRequiredMarks().isEmpty();
    if (!hasWhitelist && !hasMarks && properties.getMode() == null) {
      return;
    }
    final ConfigurableRequesterAcceptance acceptance = server.configurableRequesterAcceptance();
    if (properties.getMode() != null) {
      acceptance.mode(AuthenticationProtocol.OIDC, properties.getMode());
    }
    if (hasWhitelist) {
      acceptance.addPredicate(new WhitelistRequesterPredicate(AuthenticationProtocol.OIDC, properties.getWhitelist()));
    }
    if (hasMarks) {
      acceptance.addPredicate(
          new RequiredMarksRequesterPredicate(AuthenticationProtocol.OIDC, properties.getRequiredMarks()));
    }
  }

  /**
   * Loads the signing keys.
   *
   * @param properties the key properties
   * @param credentialFactory the credential factory
   * @return the signing keys, or {@code null} if none are configured
   * @throws Exception for errors loading a credential
   */
  static @Nullable List<SigningKey> loadSigningKeys(
      final @Nullable List<OidcConfigurationProperties.SigningKeyProperties> properties,
      final @NonNull PkiCredentialFactory credentialFactory) throws Exception {
    if (properties == null) {
      return null;
    }
    final List<SigningKey> keys = new ArrayList<>();
    for (int i = 0; i < properties.size(); i++) {
      final OidcConfigurationProperties.SigningKeyProperties key = properties.get(i);
      keys.add(new SigningKey(loadCredential(key.getCredential(), "signing[%d]".formatted(i), credentialFactory),
          key.getState(), key.isDefaultKey()));
    }
    return keys;
  }

  /**
   * Loads the decryption keys.
   *
   * @param properties the key properties
   * @param credentialFactory the credential factory
   * @return the decryption keys, or {@code null} if none are configured
   * @throws Exception for errors loading a credential
   */
  static @Nullable List<DecryptionKey> loadDecryptionKeys(
      final @Nullable List<OidcConfigurationProperties.DecryptionKeyProperties> properties,
      final @NonNull PkiCredentialFactory credentialFactory) throws Exception {
    if (properties == null) {
      return null;
    }
    final List<DecryptionKey> keys = new ArrayList<>();
    for (int i = 0; i < properties.size(); i++) {
      final OidcConfigurationProperties.DecryptionKeyProperties key = properties.get(i);
      keys.add(new DecryptionKey(loadCredential(key.getCredential(), "decryption[%d]".formatted(i), credentialFactory),
          key.getState()));
    }
    return keys;
  }

  /**
   * Loads the credential of a key.
   *
   * @param configuration the credential configuration
   * @param name the name of the key property, for the error message
   * @param credentialFactory the credential factory
   * @return the credential
   * @throws Exception for errors loading the credential
   */
  private static @NonNull PkiCredential loadCredential(
      final @Nullable PkiCredentialConfigurationProperties configuration, final @NonNull String name,
      final @NonNull PkiCredentialFactory credentialFactory) throws Exception {
    if (configuration == null) {
      throw new IllegalArgumentException(
          "Missing credential for %s.keys.%s".formatted(OidcConfigurationProperties.PREFIX, name));
    }
    return credentialFactory.createCredential(configuration);
  }

  /**
   * Turns a bound property value into a discovery parameter value. The binder gives strings, and maps for nested
   * values, where a list is a map with the keys {@code 0}, {@code 1} and so on. The strings {@code true} and
   * {@code false} become booleans.
   *
   * @param value the bound value
   * @return the parameter value
   */
  static @Nullable Object toParameterValue(final @Nullable Object value) {
    if (value instanceof final Map<?, ?> map) {
      boolean isList = !map.isEmpty();
      for (int i = 0; i < map.size() && isList; i++) {
        isList = map.containsKey(String.valueOf(i));
      }
      if (isList) {
        final List<Object> list = new ArrayList<>();
        for (int i = 0; i < map.size(); i++) {
          list.add(toParameterValue(map.get(String.valueOf(i))));
        }
        return list;
      }
      final Map<String, Object> result = new LinkedHashMap<>();
      map.forEach((k, v) -> result.put(String.valueOf(k), toParameterValue(v)));
      return result;
    }
    if (value instanceof final List<?> list) {
      return list.stream().map(OidcAutoConfiguration::toParameterValue).toList();
    }
    if ("true".equals(value) || "false".equals(value)) {
      return Boolean.valueOf((String) value);
    }
    return value;
  }

}
