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

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;

import java.util.List;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.config.AbstractProtocolConfigurer;
import se.swedenconnect.spring.authnserver.config.AuthnServerConfigurer;
import se.swedenconnect.spring.authnserver.oidc.attributes.OidcAttributeMapping;
import se.swedenconnect.spring.authnserver.oidc.keys.DecryptionKey;
import se.swedenconnect.spring.authnserver.oidc.keys.OidcKeys;
import se.swedenconnect.spring.authnserver.oidc.keys.SigningKey;
import se.swedenconnect.spring.authnserver.oidc.keys.SigningKeySelector;
import se.swedenconnect.spring.authnserver.oidc.scope.DefaultScopeRegistry;
import se.swedenconnect.spring.authnserver.oidc.scope.ScopeRegistry;
import se.swedenconnect.spring.authnserver.oidc.scope.SupportedScopesAndClaims;
import se.swedenconnect.spring.authnserver.oidc.subject.DefaultSubjectGeneratorFactory;
import se.swedenconnect.spring.authnserver.oidc.subject.SubjectGeneratorFactory;
import se.swedenconnect.spring.authnserver.oidc.web.OidcJwksEndpointFilter;

/**
 * The protocol configurer for the OpenID Provider. Register it with the {@link AuthnServerConfigurer}.
 * <p>
 * The endpoints are given relative to the OIDC path, which defaults to {@value #DEFAULT_PATH}, so the JWKS is
 * published at {@code /oidc/jwks} by default. The issuer defaults to the base URL, and the discovery document is
 * published at the issuer followed by {@value OidcDiscoveryEndpointConfigurer#WELL_KNOWN_PATH}, see
 * {@link OidcDiscoveryEndpointConfigurer}. The issuer must be the base URL or begin with it.
 * </p>
 * <p>
 * At least one active signing key is required, since ID tokens are always signed. See {@link OidcKeys} for the rules
 * of the keys, and {@link SigningKeySelector} for how the key for a client is chosen.
 * </p>
 * <p>
 * The offered scopes and the supported claims are worked out from the authentication providers, see
 * {@link SupportedScopesAndClaims}. Configured scopes replace the derived ones, and configured claims are added to
 * those of the providers.
 * </p>
 *
 * @author Martin Lindström
 */
public class OidcProviderConfigurer extends AbstractProtocolConfigurer<OidcProviderConfigurer> {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(OidcProviderConfigurer.class);

  /** The default OIDC path, {@value}. */
  public static final String DEFAULT_PATH = "/oidc";

  /** The default endpoint for publishing the JWKS, {@value}. */
  public static final String DEFAULT_JWKS_ENDPOINT = "/jwks";

  /** The issuer. */
  private String issuer;

  /** The JWKS endpoint. */
  private String jwksEndpoint = DEFAULT_JWKS_ENDPOINT;

  /** The signing keys. */
  private List<SigningKey> signingKeys;

  /** The decryption keys. */
  private List<DecryptionKey> decryptionKeys;

  /** Whether UserInfo responses are signed. */
  private boolean signUserInfo = true;

  /** The scope registry. */
  private ScopeRegistry scopeRegistry;

  /** The attribute mapping. */
  private OidcAttributeMapping attributeMapping;

  /** The subject generator factory. */
  private SubjectGeneratorFactory subjectGeneratorFactory;

  /** The configured scopes. */
  private List<String> scopes;

  /** The configured claims. */
  private List<String> claims;

  /** The UI locales. */
  private List<String> uiLocales;

  /** The discovery endpoint configurer. */
  private final OidcDiscoveryEndpointConfigurer discoveryEndpointConfigurer =
      new OidcDiscoveryEndpointConfigurer(this);

  /** The keys, created at initialization. */
  private OidcKeys keys;

  /** The signing key selector, created at initialization. */
  private SigningKeySelector signingKeySelector;

  /** The subject generator factory that is used, assigned at initialization. */
  private SubjectGeneratorFactory activeSubjectGeneratorFactory;

  /** The offered scopes and supported claims, worked out at initialization. */
  private SupportedScopesAndClaims supportedScopesAndClaims;

  /** The matcher for the JWKS endpoint. */
  private RequestMatcher jwksRequestMatcher;

  /** The matcher for the OIDC endpoints. */
  private RequestMatcher requestMatcher;

  /**
   * Constructor.
   */
  public OidcProviderConfigurer() {
    super(DEFAULT_PATH);
  }

  /** {@inheritDoc} */
  @Override
  public @Nonnull AuthenticationProtocol getProtocol() {
    return AuthenticationProtocol.OIDC;
  }

  /**
   * Assigns the issuer identifier. It must be the base URL, or begin with the base URL followed by a path. Defaults to
   * the base URL.
   *
   * @param issuer the issuer, or {@code null} for the default
   * @return this configurer
   */
  public @Nonnull OidcProviderConfigurer issuer(final @Nullable String issuer) {
    this.issuer = issuer;
    return this;
  }

  /**
   * Gets the issuer, which is the base URL unless another issuer has been assigned.
   *
   * @return the issuer
   */
  public @Nonnull String getIssuer() {
    return this.issuer != null ? this.issuer : Objects.requireNonNull(this.getServer().getBaseUrl());
  }

  /**
   * Assigns the endpoint, relative to the OIDC path, where the JWKS is published. Defaults to
   * {@value #DEFAULT_JWKS_ENDPOINT}.
   *
   * @param endpoint the endpoint
   * @return this configurer
   */
  public @Nonnull OidcProviderConfigurer jwksEndpoint(final @Nonnull String endpoint) {
    this.jwksEndpoint = Objects.requireNonNull(endpoint, "endpoint must not be null");
    return this;
  }

  /**
   * Gets the JWKS endpoint, relative to the OIDC path.
   *
   * @return the endpoint
   */
  public @Nonnull String getJwksEndpoint() {
    return this.jwksEndpoint;
  }

  /**
   * Assigns the signing keys. At least one active key is required.
   *
   * @param signingKeys the signing keys
   * @return this configurer
   */
  public @Nonnull OidcProviderConfigurer signingKeys(final @Nullable List<SigningKey> signingKeys) {
    this.signingKeys = signingKeys;
    return this;
  }

  /**
   * Assigns the decryption keys, used for encrypted request objects.
   *
   * @param decryptionKeys the decryption keys
   * @return this configurer
   */
  public @Nonnull OidcProviderConfigurer decryptionKeys(final @Nullable List<DecryptionKey> decryptionKeys) {
    this.decryptionKeys = decryptionKeys;
    return this;
  }

  /**
   * Assigns whether UserInfo responses are signed. Defaults to {@code true}. When they are, a client that has not
   * registered {@code userinfo_signed_response_alg} still gets a signed response.
   *
   * @param signUserInfo whether UserInfo responses are signed
   * @return this configurer
   */
  public @Nonnull OidcProviderConfigurer signUserInfo(final boolean signUserInfo) {
    this.signUserInfo = signUserInfo;
    return this;
  }

  /**
   * Tells whether UserInfo responses are signed.
   *
   * @return {@code true} if UserInfo responses are signed and {@code false} otherwise
   */
  public boolean isSignUserInfo() {
    return this.signUserInfo;
  }

  /**
   * Assigns the scope registry. Defaults to a {@link DefaultScopeRegistry} holding the built-in scopes.
   *
   * @param scopeRegistry the scope registry, or {@code null} for the default
   * @return this configurer
   */
  public @Nonnull OidcProviderConfigurer scopeRegistry(final @Nullable ScopeRegistry scopeRegistry) {
    this.scopeRegistry = scopeRegistry;
    return this;
  }

  /**
   * Gets the scope registry: the assigned one, or a {@link DefaultScopeRegistry}. The default is created once.
   *
   * @return the scope registry
   */
  public @Nonnull ScopeRegistry getScopeRegistry() {
    if (this.scopeRegistry == null) {
      this.scopeRegistry = new DefaultScopeRegistry();
    }
    return this.scopeRegistry;
  }

  /**
   * Assigns the mapping between generic attributes and claims. Defaults to an {@link OidcAttributeMapping} with the
   * built-in mappers.
   *
   * @param attributeMapping the mapping, or {@code null} for the default
   * @return this configurer
   */
  public @Nonnull OidcProviderConfigurer attributeMapping(final @Nullable OidcAttributeMapping attributeMapping) {
    this.attributeMapping = attributeMapping;
    return this;
  }

  /**
   * Gets the mapping between generic attributes and claims: the assigned one, or one with the built-in mappers. The
   * default is created once.
   *
   * @return the mapping
   */
  public @Nonnull OidcAttributeMapping getAttributeMapping() {
    if (this.attributeMapping == null) {
      this.attributeMapping = new OidcAttributeMapping();
    }
    return this.attributeMapping;
  }

  /**
   * Assigns the factory for subject generators. Its subject types are declared in the discovery document. Without a
   * factory, a {@link DefaultSubjectGeneratorFactory} with the subject identifier secret and hash algorithm is used.
   *
   * @param subjectGeneratorFactory the factory, or {@code null} for the default
   * @return this configurer
   */
  public @Nonnull OidcProviderConfigurer subjectGeneratorFactory(
      final @Nullable SubjectGeneratorFactory subjectGeneratorFactory) {
    this.subjectGeneratorFactory = subjectGeneratorFactory;
    return this;
  }

  /**
   * Assigns the scopes that the OpenID Provider offers. When assigned, they replace the scopes derived from the
   * authentication providers. Each scope must be in the scope registry. The {@code openid} scope is always offered.
   *
   * @param scopes the scopes, or {@code null} to derive them
   * @return this configurer
   */
  public @Nonnull OidcProviderConfigurer scopes(final @Nullable List<String> scopes) {
    this.scopes = scopes;
    return this;
  }

  /**
   * Assigns claims that are supported on top of those of the authentication providers. They also count when scopes are
   * derived.
   *
   * @param claims the claims, or {@code null}
   * @return this configurer
   */
  public @Nonnull OidcProviderConfigurer claims(final @Nullable List<String> claims) {
    this.claims = claims;
    return this;
  }

  /**
   * Assigns the languages that the user interface supports, as language tags. Published as
   * {@code ui_locales_supported}.
   *
   * @param uiLocales the language tags, or {@code null}
   * @return this configurer
   */
  public @Nonnull OidcProviderConfigurer uiLocales(final @Nullable List<String> uiLocales) {
    this.uiLocales = uiLocales;
    return this;
  }

  /**
   * Gets the languages that the user interface supports.
   *
   * @return the language tags, or {@code null}
   */
  public @Nullable List<String> getUiLocales() {
    return this.uiLocales;
  }

  /**
   * Customizes the discovery document.
   *
   * @param customizer the customizer
   * @return this configurer
   */
  public @Nonnull OidcProviderConfigurer discoveryEndpoint(
      final @Nonnull Customizer<OidcDiscoveryEndpointConfigurer> customizer) {
    customizer.customize(this.discoveryEndpointConfigurer);
    return this;
  }

  /**
   * Gets the path of the discovery endpoint relative to the application: the part of the issuer after the base URL,
   * followed by {@value OidcDiscoveryEndpointConfigurer#WELL_KNOWN_PATH}.
   *
   * @return the path
   */
  public @Nonnull String getDiscoveryEndpointPath() {
    return this.discoveryEndpointConfigurer.getEndpointPath();
  }

  /**
   * Gets the keys. Available after initialization.
   *
   * @return the keys
   */
  public @Nonnull OidcKeys getKeys() {
    return Objects.requireNonNull(this.keys, "The configurer has not been initialized");
  }

  /**
   * Gets the component that chooses the signing key for a client. Available after initialization.
   *
   * @return the signing key selector
   */
  public @Nonnull SigningKeySelector getSigningKeySelector() {
    return Objects.requireNonNull(this.signingKeySelector, "The configurer has not been initialized");
  }

  /**
   * Gets the offered scopes and the supported claims. Available after initialization.
   *
   * @return the scopes and claims
   */
  public @Nonnull SupportedScopesAndClaims getSupportedScopesAndClaims() {
    return Objects.requireNonNull(this.supportedScopesAndClaims, "The configurer has not been initialized");
  }

  /**
   * Gets the subject generator factory that is used: the assigned one, or a {@link DefaultSubjectGeneratorFactory}.
   * Available after initialization.
   *
   * @return the factory
   */
  public @Nonnull SubjectGeneratorFactory getActiveSubjectGeneratorFactory() {
    return Objects.requireNonNull(this.activeSubjectGeneratorFactory, "The configurer has not been initialized");
  }

  /** {@inheritDoc} */
  @Override
  protected void init(final @Nonnull HttpSecurity http) {
    this.validate();

    this.keys = new OidcKeys(Objects.requireNonNull(this.signingKeys), this.decryptionKeys);
    this.signingKeySelector = new SigningKeySelector(this.keys);

    if (this.subjectGeneratorFactory != null) {
      this.activeSubjectGeneratorFactory = this.subjectGeneratorFactory;
    }
    else {
      final DefaultSubjectGeneratorFactory factory = new DefaultSubjectGeneratorFactory(this.getIssuer());
      factory.setSecret(this.getSubjectIdentifierSecret());
      factory.setHashAlgorithm(this.getSubjectIdentifierHashAlgorithm());
      this.activeSubjectGeneratorFactory = factory;
    }

    this.supportedScopesAndClaims = SupportedScopesAndClaims.resolve(this.getServer().getAuthenticationProviders(),
        this.getAttributeMapping(), this.getScopeRegistry(), this.scopes, this.claims);

    this.jwksRequestMatcher =
        PathPatternRequestMatcher.pathPattern(HttpMethod.GET, this.getEndpointPath(this.jwksEndpoint));
    this.discoveryEndpointConfigurer.init();
    this.requestMatcher =
        new OrRequestMatcher(this.jwksRequestMatcher, this.discoveryEndpointConfigurer.getRequestMatcher());

    log.info("OpenID Provider '{}' - signing keys: {}, decryption keys: {}", this.getIssuer(),
        this.keys.getSigningKeys(), this.keys.getDecryptionKeys());
  }

  /** {@inheritDoc} */
  @Override
  protected void configure(final @Nonnull HttpSecurity http) {
    http.addFilterBefore(this.postProcess(new OidcJwksEndpointFilter(this.keys, this.jwksRequestMatcher)),
        AbstractPreAuthenticatedProcessingFilter.class);
    this.discoveryEndpointConfigurer.configure(http);
  }

  /** {@inheritDoc} */
  @Override
  protected @Nonnull RequestMatcher getRequestMatcher() {
    return Objects.requireNonNull(this.requestMatcher, "The configurer has not been initialized");
  }

  /**
   * Gets the discovery endpoint configurer.
   *
   * @return the discovery endpoint configurer
   */
  @Nonnull
  OidcDiscoveryEndpointConfigurer getDiscoveryEndpointConfigurer() {
    return this.discoveryEndpointConfigurer;
  }

  /**
   * Makes a post processing available to the sub-configurers.
   *
   * @param object the object
   * @param <O> the type
   * @return the processed object
   */
  @Nonnull
  <O> O postProcessObject(final @Nonnull O object) {
    return this.postProcess(object);
  }

  /**
   * Checks that the values required by the OpenID Provider are set and valid.
   *
   * @throws IllegalArgumentException if a value is missing or invalid
   */
  private void validate() {
    final String baseUrl = Objects.requireNonNull(this.getServer().getBaseUrl());
    if (this.issuer != null) {
      AuthnServerConfigurer.assertBaseUrl(this.issuer, "OIDC issuer");
      if (!this.issuer.equals(baseUrl) && !this.issuer.startsWith(baseUrl + "/")) {
        throw new IllegalArgumentException("OIDC issuer '%s' must be the base URL '%s' or begin with it"
            .formatted(this.issuer, baseUrl));
      }
    }
    if (this.signingKeys == null || this.signingKeys.isEmpty()) {
      throw new IllegalArgumentException("Missing OIDC signing key - ID tokens must be signed, assign at least one "
          + "active signing key (authn-server.oidc.keys.signing)");
    }
    if (!this.jwksEndpoint.startsWith("/")) {
      throw new IllegalArgumentException(
          "Invalid OIDC jwks endpoint '%s' - it must begin with /".formatted(this.jwksEndpoint));
    }
  }

}
