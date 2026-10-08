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

import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;

import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.authentication.provider.UserAuthenticationProvider;
import se.swedenconnect.spring.authnserver.config.AbstractProtocolConfigurer;
import se.swedenconnect.spring.authnserver.config.AuthnServerConfigurer;
import se.swedenconnect.spring.authnserver.entity.EntityInformation;
import se.swedenconnect.spring.authnserver.oidc.attributes.OidcAttributeMapping;
import se.swedenconnect.spring.authnserver.oidc.attributes.requested.OidcRequestedAttributeResolver;
import se.swedenconnect.spring.authnserver.oidc.authnrequest.ClientKeyResolver;
import se.swedenconnect.spring.authnserver.oidc.authnrequest.DefaultClientKeyResolver;
import se.swedenconnect.spring.authnserver.oidc.authnrequest.HttpRequestUriFetcher;
import se.swedenconnect.spring.authnserver.oidc.authnrequest.OidcAuthnRequestAuthenticationConverter;
import se.swedenconnect.spring.authnserver.oidc.authnrequest.OidcAuthnRequestAuthenticationProvider;
import se.swedenconnect.spring.authnserver.oidc.authnrequest.RequestObjectDecoder;
import se.swedenconnect.spring.authnserver.oidc.federation.OidcEntityMetadata;
import se.swedenconnect.spring.authnserver.oidc.keys.DecryptionKey;
import se.swedenconnect.spring.authnserver.oidc.keys.OidcKeys;
import se.swedenconnect.spring.authnserver.oidc.keys.SigningKey;
import se.swedenconnect.spring.authnserver.oidc.keys.SigningKeySelector;
import se.swedenconnect.spring.authnserver.oidc.response.OidcResponseSender;
import se.swedenconnect.spring.authnserver.oidc.response.OidcUserAuthenticationResponder;
import se.swedenconnect.spring.authnserver.oidc.scope.DefaultScopeRegistry;
import se.swedenconnect.spring.authnserver.oidc.scope.ScopeRegistry;
import se.swedenconnect.spring.authnserver.oidc.scope.SupportedScopesAndClaims;
import se.swedenconnect.spring.authnserver.oidc.subject.DefaultSubjectGeneratorFactory;
import se.swedenconnect.spring.authnserver.oidc.subject.SubjectGeneratorFactory;
import se.swedenconnect.spring.authnserver.oidc.token.AccessTokenStore;
import se.swedenconnect.spring.authnserver.oidc.token.AuthorizationCodeStore;
import se.swedenconnect.spring.authnserver.oidc.token.ClientAssertionReplayCache;
import se.swedenconnect.spring.authnserver.oidc.token.ClientAuthenticator;
import se.swedenconnect.spring.authnserver.oidc.token.ClientEncryption;
import se.swedenconnect.spring.authnserver.oidc.token.IdTokenBuilder;
import se.swedenconnect.spring.authnserver.oidc.token.InMemoryAccessTokenStore;
import se.swedenconnect.spring.authnserver.oidc.token.InMemoryAuthorizationCodeStore;
import se.swedenconnect.spring.authnserver.oidc.token.InMemoryClientAssertionReplayCache;
import se.swedenconnect.spring.authnserver.oidc.token.TokenRequestProcessor;
import se.swedenconnect.spring.authnserver.oidc.web.OidcAuthnRequestProcessingFilter;
import se.swedenconnect.spring.authnserver.oidc.web.OidcErrorResponseProcessingFilter;
import se.swedenconnect.spring.authnserver.oidc.web.OidcJwksEndpointFilter;
import se.swedenconnect.spring.authnserver.oidc.web.OidcResumedAuthenticationHandler;
import se.swedenconnect.spring.authnserver.oidc.userinfo.UserInfoRequestProcessor;
import se.swedenconnect.spring.authnserver.oidc.web.OidcTokenEndpointFilter;
import se.swedenconnect.spring.authnserver.oidc.web.OidcUserInfoEndpointFilter;
import se.swedenconnect.spring.authnserver.oidc.web.OidcUserAuthenticationProcessingFilter;
import se.swedenconnect.spring.authnserver.web.ResumedAuthenticationHandler;
import se.swedenconnect.spring.authnserver.web.UserAuthenticationFlow;

/**
 * The protocol configurer for the OpenID Provider. Register it with the {@link AuthnServerConfigurer}.
 * <p>
 * The endpoints are given relative to the OIDC path, which defaults to {@value #DEFAULT_PATH}, so the JWKS is
 * published at {@code /oidc/jwks} and the authorization endpoint is {@code /oidc/authorize} by default. The issuer
 * defaults to the base URL, and the discovery document is published at the issuer followed by
 * {@value OidcDiscoveryEndpointConfigurer#WELL_KNOWN_PATH}, see {@link OidcDiscoveryEndpointConfigurer}. The issuer
 * must be the base URL or begin with it.
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
 * <p>
 * Authentication requests are received on the authorization endpoint, with GET or POST, and processed by
 * {@link OidcAuthnRequestAuthenticationConverter} and {@link OidcAuthnRequestAuthenticationProvider}. The clients are
 * found in the client registry. The settings for PKCE, signed request objects and {@code state} are held here, and
 * the processing components can be replaced with {@link #authnRequestProcessor(Customizer)}.
 * </p>
 * <p>
 * A processed request is handed to the authentication providers through the {@link UserAuthenticationFlow}, and the
 * client gets an authorization code, which it exchanges for an access token and an ID token at the token endpoint,
 * {@code /oidc/token} by default. The OpenID Connect attribute producers and release voters come before the shared
 * ones. The access token gives the client the UserInfo claims at the UserInfo endpoint, {@code /oidc/userinfo} by
 * default, see {@link UserInfoRequestProcessor}.
 * </p>
 * <p>
 * The OpenID Provider may be a member of an OpenID Federation, see {@link #federation(Customizer)}. The descriptive
 * parameters of its metadata come from the shared entity information of the server, see {@link #getEntityMetadata()}.
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

  /** The default authorization endpoint, {@value}. */
  public static final String DEFAULT_AUTHORIZATION_ENDPOINT = "/authorize";

  /** The default token endpoint, {@value}. */
  public static final String DEFAULT_TOKEN_ENDPOINT = "/token";

  /** The default UserInfo endpoint, {@value}. */
  public static final String DEFAULT_USERINFO_ENDPOINT = "/userinfo";

  /** The authorization code lifetime above which a warning is logged, 10 minutes (RFC 6749, Section 4.1.2). */
  public static final Duration MAX_RECOMMENDED_CODE_LIFETIME = Duration.ofMinutes(10);

  /** The ID token lifetime above which a warning is logged, 5 minutes (Swedish OpenID Connect Profile, 3.2.1). */
  public static final Duration MAX_RECOMMENDED_ID_TOKEN_LIFETIME = Duration.ofMinutes(5);

  /** The issuer. */
  private String issuer;

  /** The JWKS endpoint. */
  private String jwksEndpoint = DEFAULT_JWKS_ENDPOINT;

  /** The authorization endpoint. */
  private String authorizationEndpoint = DEFAULT_AUTHORIZATION_ENDPOINT;

  /** Whether PKCE is required. */
  private boolean requirePkce = false;

  /** Whether request objects must be signed. */
  private boolean requireSignedRequestObject = false;

  /** Whether {@code state} is required. */
  private boolean requireState = true;

  /** Whether a request without {@code prompt} is treated as {@code prompt=login}. */
  private boolean loginWithoutPrompt = true;

  /** The token endpoint. */
  private String tokenEndpoint = DEFAULT_TOKEN_ENDPOINT;

  /** The UserInfo endpoint. */
  private String userInfoEndpoint = DEFAULT_USERINFO_ENDPOINT;

  /** The authorization code lifetime. */
  private Duration authorizationCodeLifetime = OidcUserAuthenticationResponder.DEFAULT_CODE_LIFETIME;

  /** The access token lifetime. */
  private Duration accessTokenLifetime = TokenRequestProcessor.DEFAULT_ACCESS_TOKEN_LIFETIME;

  /** Whether access tokens may only be used once. */
  private boolean singleUseAccessTokens = true;

  /** The ID token lifetime. */
  private Duration idTokenLifetime = IdTokenBuilder.DEFAULT_LIFETIME;

  /** The maximum age of a JWT signed by a client, or {@code null} for no limit. */
  private Duration maxJwtAge;

  /** The enabled client authentication methods. */
  private Set<ClientAuthenticationMethod> clientAuthenticationMethods =
      Set.of(ClientAuthenticationMethod.PRIVATE_KEY_JWT);

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

  /** The configurer for the request processing components. */
  private final OidcAuthnRequestProcessorConfigurer authnRequestProcessorConfigurer =
      new OidcAuthnRequestProcessorConfigurer();

  /** The discovery endpoint configurer. */
  private final OidcDiscoveryEndpointConfigurer discoveryEndpointConfigurer =
      new OidcDiscoveryEndpointConfigurer(this);

  /** The OpenID Federation configurer. */
  private final OidcFederationConfigurer federationConfigurer = new OidcFederationConfigurer(this);

  /** Overrides of the shared entity information, or {@code null}. */
  private EntityInformation entityInformation;

  /** Values of the descriptive metadata parameters, overriding those taken from the entity information. */
  private OidcEntityMetadata entityMetadata;

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

  /** The matcher for the authorization endpoint. */
  private RequestMatcher authorizationRequestMatcher;

  /** The matcher for the token endpoint. */
  private RequestMatcher tokenRequestMatcher;

  /** The matcher for the UserInfo endpoint. */
  private RequestMatcher userInfoRequestMatcher;

  /** Finds the keys of clients, created at initialization. */
  private ClientKeyResolver clientKeyResolver;

  /** The authorization code store, created at initialization. */
  private AuthorizationCodeStore authorizationCodeStore;

  /** The access token store, created at initialization. */
  private AccessTokenStore accessTokenStore;

  /** The client assertion replay cache, created at initialization. */
  private ClientAssertionReplayCache clientAssertionReplayCache;

  /** Continues the OIDC flow on the resume paths, created when the configurer is applied. */
  private ResumedAuthenticationHandler resumedAuthenticationHandler;

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
  public @NonNull AuthenticationProtocol getProtocol() {
    return AuthenticationProtocol.OIDC;
  }

  /**
   * Assigns the issuer identifier. It must be the base URL, or begin with the base URL followed by a path. Defaults to
   * the base URL.
   *
   * @param issuer the issuer, or {@code null} for the default
   * @return this configurer
   */
  public @NonNull OidcProviderConfigurer issuer(final @Nullable String issuer) {
    this.issuer = issuer;
    return this;
  }

  /**
   * Gets the issuer, which is the base URL unless another issuer has been assigned.
   *
   * @return the issuer
   */
  public @NonNull String getIssuer() {
    return this.issuer != null ? this.issuer : Objects.requireNonNull(this.getServer().getBaseUrl());
  }

  /**
   * Assigns the endpoint, relative to the OIDC path, where the JWKS is published. Defaults to
   * {@value #DEFAULT_JWKS_ENDPOINT}.
   *
   * @param endpoint the endpoint
   * @return this configurer
   */
  public @NonNull OidcProviderConfigurer jwksEndpoint(final @NonNull String endpoint) {
    this.jwksEndpoint = Objects.requireNonNull(endpoint, "endpoint must not be null");
    return this;
  }

  /**
   * Gets the JWKS endpoint, relative to the OIDC path.
   *
   * @return the endpoint
   */
  public @NonNull String getJwksEndpoint() {
    return this.jwksEndpoint;
  }

  /**
   * Assigns the authorization endpoint, relative to the OIDC path, where authentication requests are received with GET
   * and POST. Defaults to {@value #DEFAULT_AUTHORIZATION_ENDPOINT}.
   *
   * @param endpoint the endpoint
   * @return this configurer
   */
  public @NonNull OidcProviderConfigurer authorizationEndpoint(final @NonNull String endpoint) {
    this.authorizationEndpoint = Objects.requireNonNull(endpoint, "endpoint must not be null");
    return this;
  }

  /**
   * Gets the authorization endpoint, relative to the OIDC path.
   *
   * @return the endpoint
   */
  public @NonNull String getAuthorizationEndpoint() {
    return this.authorizationEndpoint;
  }

  /**
   * Assigns whether PKCE is required. Defaults to {@code false}, which means that PKCE is optional. The {@code plain}
   * method is never accepted. Public clients, with the token endpoint authentication method {@code none}, are not
   * supported.
   *
   * @param requirePkce whether PKCE is required
   * @return this configurer
   */
  public @NonNull OidcProviderConfigurer requirePkce(final boolean requirePkce) {
    this.requirePkce = requirePkce;
    return this;
  }

  /**
   * Tells whether PKCE is required.
   *
   * @return {@code true} if PKCE is required, and {@code false} if it is optional
   */
  public boolean isRequirePkce() {
    return this.requirePkce;
  }

  /**
   * Assigns whether request objects must be signed. Defaults to {@code false}, which means that an unsigned request
   * object is accepted unless the client has registered {@code request_object_signing_alg}.
   *
   * @param requireSignedRequestObject whether request objects must be signed
   * @return this configurer
   */
  public @NonNull OidcProviderConfigurer requireSignedRequestObject(final boolean requireSignedRequestObject) {
    this.requireSignedRequestObject = requireSignedRequestObject;
    return this;
  }

  /**
   * Tells whether request objects must be signed.
   *
   * @return {@code true} if request objects must be signed and {@code false} otherwise
   */
  public boolean isRequireSignedRequestObject() {
    return this.requireSignedRequestObject;
  }

  /**
   * Assigns whether authentication requests must carry {@code state}. Defaults to {@code true}, which means that a
   * request without {@code state} is rejected with {@code invalid_request}. When {@code false}, such a request is
   * accepted and its response carries no {@code state}.
   *
   * @param requireState whether {@code state} is required
   * @return this configurer
   */
  public @NonNull OidcProviderConfigurer requireState(final boolean requireState) {
    this.requireState = requireState;
    return this;
  }

  /**
   * Tells whether authentication requests must carry {@code state}.
   *
   * @return {@code true} if {@code state} is required and {@code false} otherwise
   */
  public boolean isRequireState() {
    return this.requireState;
  }

  /**
   * Assigns whether an authentication request without {@code prompt} is treated as {@code prompt=login}, as the OpenID
   * Connect Profile for Sweden Connect, Section 2.2.1, requires. Defaults to {@code true}. When {@code false}, such a
   * request may be answered with single sign-on.
   *
   * @param loginWithoutPrompt whether a request without {@code prompt} is treated as {@code prompt=login}
   * @return this configurer
   */
  public @NonNull OidcProviderConfigurer loginWithoutPrompt(final boolean loginWithoutPrompt) {
    this.loginWithoutPrompt = loginWithoutPrompt;
    return this;
  }

  /**
   * Tells whether an authentication request without {@code prompt} is treated as {@code prompt=login}.
   *
   * @return {@code true} if a request without {@code prompt} is treated as {@code prompt=login}
   */
  public boolean isLoginWithoutPrompt() {
    return this.loginWithoutPrompt;
  }

  /**
   * Assigns the token endpoint, relative to the OIDC path. Defaults to {@value #DEFAULT_TOKEN_ENDPOINT}.
   *
   * @param endpoint the endpoint
   * @return this configurer
   */
  public @NonNull OidcProviderConfigurer tokenEndpoint(final @NonNull String endpoint) {
    this.tokenEndpoint = Objects.requireNonNull(endpoint, "endpoint must not be null");
    return this;
  }

  /**
   * Gets the token endpoint, relative to the OIDC path.
   *
   * @return the endpoint
   */
  public @NonNull String getTokenEndpoint() {
    return this.tokenEndpoint;
  }

  /**
   * Assigns the UserInfo endpoint, relative to the OIDC path, where UserInfo requests are received with GET and POST.
   * Defaults to {@value #DEFAULT_USERINFO_ENDPOINT}.
   *
   * @param endpoint the endpoint
   * @return this configurer
   */
  public @NonNull OidcProviderConfigurer userInfoEndpoint(final @NonNull String endpoint) {
    this.userInfoEndpoint = Objects.requireNonNull(endpoint, "endpoint must not be null");
    return this;
  }

  /**
   * Gets the UserInfo endpoint, relative to the OIDC path.
   *
   * @return the endpoint
   */
  public @NonNull String getUserInfoEndpoint() {
    return this.userInfoEndpoint;
  }

  /**
   * Assigns the authorization code lifetime. Defaults to 1 minute. A lifetime above 10 minutes, the maximum that RFC
   * 6749, Section 4.1.2, recommends, is logged as a warning at startup.
   *
   * @param lifetime the lifetime
   * @return this configurer
   */
  public @NonNull OidcProviderConfigurer authorizationCodeLifetime(final @NonNull Duration lifetime) {
    this.authorizationCodeLifetime = Objects.requireNonNull(lifetime, "lifetime must not be null");
    return this;
  }

  /**
   * Gets the authorization code lifetime.
   *
   * @return the lifetime
   */
  public @NonNull Duration getAuthorizationCodeLifetime() {
    return this.authorizationCodeLifetime;
  }

  /**
   * Assigns the access token lifetime. Defaults to 5 minutes.
   *
   * @param lifetime the lifetime
   * @return this configurer
   */
  public @NonNull OidcProviderConfigurer accessTokenLifetime(final @NonNull Duration lifetime) {
    this.accessTokenLifetime = Objects.requireNonNull(lifetime, "lifetime must not be null");
    return this;
  }

  /**
   * Gets the access token lifetime.
   *
   * @return the lifetime
   */
  public @NonNull Duration getAccessTokenLifetime() {
    return this.accessTokenLifetime;
  }

  /**
   * Assigns whether an access token may only be used once, at the UserInfo endpoint. Defaults to {@code true}, which
   * means that the first successful UserInfo request consumes the token. When {@code false}, the token may be used
   * until it expires.
   *
   * @param singleUseAccessTokens whether access tokens may only be used once
   * @return this configurer
   */
  public @NonNull OidcProviderConfigurer singleUseAccessTokens(final boolean singleUseAccessTokens) {
    this.singleUseAccessTokens = singleUseAccessTokens;
    return this;
  }

  /**
   * Tells whether an access token may only be used once.
   *
   * @return {@code true} if access tokens may only be used once and {@code false} otherwise
   */
  public boolean isSingleUseAccessTokens() {
    return this.singleUseAccessTokens;
  }

  /**
   * Assigns the ID token lifetime. Defaults to 5 minutes. A lifetime above 5 minutes, the maximum of the Swedish
   * OpenID Connect Profile, Section 3.2.1, is logged as a warning at startup.
   *
   * @param lifetime the lifetime
   * @return this configurer
   */
  public @NonNull OidcProviderConfigurer idTokenLifetime(final @NonNull Duration lifetime) {
    this.idTokenLifetime = Objects.requireNonNull(lifetime, "lifetime must not be null");
    return this;
  }

  /**
   * Gets the ID token lifetime.
   *
   * @return the lifetime
   */
  public @NonNull Duration getIdTokenLifetime() {
    return this.idTokenLifetime;
  }

  /**
   * Assigns the maximum age of a JWT that a client signs, measured from its {@code iat}. It applies to signed request
   * objects, signature request JWTs and client assertions, and the clock skew is added to it. A JWT without
   * {@code iat} is accepted. Defaults to {@code null}, which means that the age is not checked. The value must be
   * positive.
   *
   * @param maxJwtAge the maximum age, or {@code null} for no limit
   * @return this configurer
   */
  public @NonNull OidcProviderConfigurer maxJwtAge(final @Nullable Duration maxJwtAge) {
    this.maxJwtAge = maxJwtAge;
    return this;
  }

  /**
   * Gets the maximum age of a JWT that a client signs.
   *
   * @return the maximum age, or {@code null} if the age is not checked
   */
  public @Nullable Duration getMaxJwtAge() {
    return this.maxJwtAge;
  }

  /**
   * Assigns the client authentication methods that are enabled at the token endpoint. Defaults to
   * {@code private_key_jwt}. The methods that can be enabled are {@code private_key_jwt}, {@code client_secret_basic},
   * {@code client_secret_post} and {@code client_secret_jwt}; {@code none} is not supported.
   *
   * @param methods the methods
   * @return this configurer
   */
  public @NonNull OidcProviderConfigurer clientAuthenticationMethods(
      final @NonNull Set<ClientAuthenticationMethod> methods) {
    this.clientAuthenticationMethods = Set.copyOf(Objects.requireNonNull(methods, "methods must not be null"));
    return this;
  }

  /**
   * Gets the client authentication methods that are enabled at the token endpoint.
   *
   * @return the methods
   */
  public @NonNull Set<ClientAuthenticationMethod> getClientAuthenticationMethods() {
    return this.clientAuthenticationMethods;
  }

  /**
   * Gets the access token store. Available after initialization.
   *
   * @return the access token store
   */
  public @NonNull AccessTokenStore getAccessTokenStore() {
    return Objects.requireNonNull(this.accessTokenStore, "The configurer has not been initialized");
  }

  /**
   * Customizes the components that process authentication requests and send responses.
   *
   * @param customizer the customizer
   * @return this configurer
   */
  public @NonNull OidcProviderConfigurer authnRequestProcessor(
      final @NonNull Customizer<OidcAuthnRequestProcessorConfigurer> customizer) {
    customizer.customize(this.authnRequestProcessorConfigurer);
    return this;
  }

  /**
   * Assigns the signing keys. At least one active key is required.
   *
   * @param signingKeys the signing keys
   * @return this configurer
   */
  public @NonNull OidcProviderConfigurer signingKeys(final @Nullable List<SigningKey> signingKeys) {
    this.signingKeys = signingKeys;
    return this;
  }

  /**
   * Assigns the decryption keys, used for encrypted request objects.
   *
   * @param decryptionKeys the decryption keys
   * @return this configurer
   */
  public @NonNull OidcProviderConfigurer decryptionKeys(final @Nullable List<DecryptionKey> decryptionKeys) {
    this.decryptionKeys = decryptionKeys;
    return this;
  }

  /**
   * Assigns whether UserInfo responses are signed. Defaults to {@code true}. When they are, a client that has not
   * registered {@code userinfo_signed_response_alg} still gets a signed response. When they are not, a client gets
   * plain JSON unless it has registered {@code userinfo_signed_response_alg}.
   *
   * @param signUserInfo whether UserInfo responses are signed
   * @return this configurer
   */
  public @NonNull OidcProviderConfigurer signUserInfo(final boolean signUserInfo) {
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
  public @NonNull OidcProviderConfigurer scopeRegistry(final @Nullable ScopeRegistry scopeRegistry) {
    this.scopeRegistry = scopeRegistry;
    return this;
  }

  /**
   * Gets the scope registry: the assigned one, or a {@link DefaultScopeRegistry}. The default is created once.
   *
   * @return the scope registry
   */
  public @NonNull ScopeRegistry getScopeRegistry() {
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
  public @NonNull OidcProviderConfigurer attributeMapping(final @Nullable OidcAttributeMapping attributeMapping) {
    this.attributeMapping = attributeMapping;
    return this;
  }

  /**
   * Gets the mapping between generic attributes and claims: the assigned one, or one with the built-in mappers. The
   * default is created once.
   *
   * @return the mapping
   */
  public @NonNull OidcAttributeMapping getAttributeMapping() {
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
  public @NonNull OidcProviderConfigurer subjectGeneratorFactory(
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
  public @NonNull OidcProviderConfigurer scopes(final @Nullable List<String> scopes) {
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
  public @NonNull OidcProviderConfigurer claims(final @Nullable List<String> claims) {
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
  public @NonNull OidcProviderConfigurer uiLocales(final @Nullable List<String> uiLocales) {
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
  public @NonNull OidcProviderConfigurer discoveryEndpoint(
      final @NonNull Customizer<OidcDiscoveryEndpointConfigurer> customizer) {
    customizer.customize(this.discoveryEndpointConfigurer);
    return this;
  }

  /**
   * Customizes the OpenID Provider as a member of an OpenID Federation, see {@link OidcFederationConfigurer}.
   *
   * @param customizer the customizer
   * @return this configurer
   */
  public @NonNull OidcProviderConfigurer federation(final @NonNull Customizer<OidcFederationConfigurer> customizer) {
    customizer.customize(this.federationConfigurer);
    return this;
  }

  /**
   * Gets the OpenID Federation configurer.
   *
   * @return the federation configurer
   */
  public @NonNull OidcFederationConfigurer getFederation() {
    return this.federationConfigurer;
  }

  /**
   * Assigns overrides of the shared entity information of the server for OpenID Connect. The values assigned here
   * replace the shared values, see {@link EntityInformation#overriddenBy(EntityInformation)}.
   *
   * @param entityInformation the overrides, or {@code null}
   * @return this configurer
   */
  public @NonNull OidcProviderConfigurer entityInformation(final @Nullable EntityInformation entityInformation) {
    this.entityInformation = entityInformation;
    return this;
  }

  /**
   * Assigns values of the descriptive metadata parameters, such as {@code logo_uri} or {@code contacts}. A value
   * assigned here replaces the value that is otherwise taken from the entity information.
   *
   * @param entityMetadata the values, or {@code null}
   * @return this configurer
   */
  public @NonNull OidcProviderConfigurer entityMetadata(final @Nullable OidcEntityMetadata entityMetadata) {
    this.entityMetadata = entityMetadata;
    return this;
  }

  /**
   * Gets the descriptive metadata parameters of the OpenID Provider: the shared entity information of the server, with
   * the OpenID Connect overrides applied, mapped as described in {@link OidcEntityMetadata#from(EntityInformation,
   * String)}, and then the assigned parameter values applied.
   *
   * @return the descriptive metadata parameters
   */
  public @NonNull OidcEntityMetadata getEntityMetadata() {
    final EntityInformation information = this.getServer().getEntityInformation().overriddenBy(this.entityInformation);
    return OidcEntityMetadata.from(information, Objects.requireNonNull(this.getServer().getBaseUrl()))
        .overriddenBy(this.entityMetadata);
  }

  /**
   * Gets the path of the discovery endpoint relative to the application: the part of the issuer after the base URL,
   * followed by {@value OidcDiscoveryEndpointConfigurer#WELL_KNOWN_PATH}.
   *
   * @return the path
   */
  public @NonNull String getDiscoveryEndpointPath() {
    return this.discoveryEndpointConfigurer.getEndpointPath();
  }

  /**
   * Gets the keys. Available after initialization.
   *
   * @return the keys
   */
  public @NonNull OidcKeys getKeys() {
    return Objects.requireNonNull(this.keys, "The configurer has not been initialized");
  }

  /**
   * Gets the component that chooses the signing key for a client. Available after initialization.
   *
   * @return the signing key selector
   */
  public @NonNull SigningKeySelector getSigningKeySelector() {
    return Objects.requireNonNull(this.signingKeySelector, "The configurer has not been initialized");
  }

  /**
   * Gets the offered scopes and the supported claims. Available after initialization.
   *
   * @return the scopes and claims
   */
  public @NonNull SupportedScopesAndClaims getSupportedScopesAndClaims() {
    return Objects.requireNonNull(this.supportedScopesAndClaims, "The configurer has not been initialized");
  }

  /**
   * Gets the subject generator factory that is used: the assigned one, or a {@link DefaultSubjectGeneratorFactory}.
   * Available after initialization.
   *
   * @return the factory
   */
  public @NonNull SubjectGeneratorFactory getActiveSubjectGeneratorFactory() {
    return Objects.requireNonNull(this.activeSubjectGeneratorFactory, "The configurer has not been initialized");
  }

  /** {@inheritDoc} */
  @Override
  protected void init(final @NonNull HttpSecurity http) {
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
    this.authorizationRequestMatcher = new OrRequestMatcher(
        PathPatternRequestMatcher.pathPattern(HttpMethod.GET, this.getEndpointPath(this.authorizationEndpoint)),
        PathPatternRequestMatcher.pathPattern(HttpMethod.POST, this.getEndpointPath(this.authorizationEndpoint)));
    this.tokenRequestMatcher =
        PathPatternRequestMatcher.pathPattern(HttpMethod.POST, this.getEndpointPath(this.tokenEndpoint));
    this.userInfoRequestMatcher = new OrRequestMatcher(
        PathPatternRequestMatcher.pathPattern(HttpMethod.GET, this.getEndpointPath(this.userInfoEndpoint)),
        PathPatternRequestMatcher.pathPattern(HttpMethod.POST, this.getEndpointPath(this.userInfoEndpoint)));
    this.discoveryEndpointConfigurer.init();
    this.federationConfigurer.init();
    final List<RequestMatcher> matchers = new ArrayList<>(List.of(this.jwksRequestMatcher,
        this.authorizationRequestMatcher, this.tokenRequestMatcher, this.userInfoRequestMatcher,
        this.discoveryEndpointConfigurer.getRequestMatcher()));
    if (this.federationConfigurer.getRequestMatcher() != null) {
      matchers.add(this.federationConfigurer.getRequestMatcher());
    }
    this.requestMatcher = new OrRequestMatcher(matchers);

    final OidcAuthnRequestProcessorConfigurer components = this.authnRequestProcessorConfigurer;
    this.clientKeyResolver =
        Objects.requireNonNullElseGet(components.getClientKeyResolver(), DefaultClientKeyResolver::new);
    this.authorizationCodeStore =
        Objects.requireNonNullElseGet(components.getAuthorizationCodeStore(), InMemoryAuthorizationCodeStore::new);
    this.accessTokenStore =
        Objects.requireNonNullElseGet(components.getAccessTokenStore(), InMemoryAccessTokenStore::new);
    this.clientAssertionReplayCache = Objects.requireNonNullElseGet(components.getClientAssertionReplayCache(),
        InMemoryClientAssertionReplayCache::new);

    if (this.authorizationCodeLifetime.compareTo(MAX_RECOMMENDED_CODE_LIFETIME) > 0) {
      log.warn("The OIDC authorization code lifetime {} is longer than the 10 minutes that RFC 6749 recommends",
          this.authorizationCodeLifetime);
    }
    if (this.idTokenLifetime.compareTo(MAX_RECOMMENDED_ID_TOKEN_LIFETIME) > 0) {
      log.warn("The OIDC ID token lifetime {} is longer than the 5 minutes that the Swedish OpenID Connect Profile "
          + "allows", this.idTokenLifetime);
    }

    log.info("OpenID Provider '{}' - signing keys: {}, decryption keys: {}, client authentication methods: {}",
        this.getIssuer(), this.keys.getSigningKeys(), this.keys.getDecryptionKeys(),
        this.clientAuthenticationMethods);
  }

  /** {@inheritDoc} */
  @Override
  protected void configure(final @NonNull HttpSecurity http) {
    http.addFilterBefore(this.postProcess(new OidcJwksEndpointFilter(this.keys, this.jwksRequestMatcher)),
        AbstractPreAuthenticatedProcessingFilter.class);
    this.discoveryEndpointConfigurer.configure(http);
    this.federationConfigurer.configure(http,
        this.discoveryEndpointConfigurer.getProviderMetadata().toJSONObject());

    final OidcAuthnRequestProcessorConfigurer components = this.authnRequestProcessorConfigurer;
    final AuthnServerConfigurer server = this.getServer();
    final IdTokenBuilder idTokenBuilder = new IdTokenBuilder(this.getIssuer(), this.signingKeySelector,
        this.clientKeyResolver, this.idTokenLifetime);

    // Error responses ...
    //
    final OidcResponseSender responseSender = new OidcResponseSender();
    if (components.getResponsePage() != null) {
      responseSender.setResponsePage(components.getResponsePage());
    }
    final OidcErrorResponseProcessingFilter errorFilter =
        new OidcErrorResponseProcessingFilter(this.authorizationRequestMatcher, responseSender);
    errorFilter.setEventPublisher(server.getEventPublisher());
    http.addFilterAfter(this.postProcess(errorFilter), ExceptionTranslationFilter.class);

    // Request processing ...
    //
    final RequestObjectDecoder requestObjectDecoder = new RequestObjectDecoder(this.keys, this.clientKeyResolver,
        this.getIssuer(), this.getEndpointUrl(this.authorizationEndpoint), this.getClockSkew());
    requestObjectDecoder.setMaxJwtAge(this.maxJwtAge);
    final OidcAuthnRequestAuthenticationConverter converter = new OidcAuthnRequestAuthenticationConverter(
        server.getClientRegistry(), requestObjectDecoder,
        Objects.requireNonNullElseGet(components.getRequestUriFetcher(), HttpRequestUriFetcher::new));
    final OidcAuthnRequestAuthenticationProvider provider = new OidcAuthnRequestAuthenticationProvider(
        this.keys, this.getIssuer(), server.getClientRegistry(), server.getRequesterAcceptance(),
        Objects.requireNonNullElseGet(components.getRequestedAttributeResolver(),
            () -> new OidcRequestedAttributeResolver(this.getAttributeMapping(), this.getScopeRegistry())),
        requestObjectDecoder, this.supportedScopesAndClaims.scopes(), this.getSupportedAuthnContextUris());
    provider.setSupportsUserMessage(this.isSupportsUserMessage());
    provider.setRequirePkce(this.requirePkce);
    provider.setRequireSignedRequestObject(this.requireSignedRequestObject);
    provider.setRequireState(this.requireState);
    provider.setLoginWithoutPrompt(this.loginWithoutPrompt);
    provider.setIdTokenBuilder(idTokenBuilder);

    final OidcAuthnRequestProcessingFilter processingFilter =
        new OidcAuthnRequestProcessingFilter(this.authorizationRequestMatcher, converter, provider);
    processingFilter.setEventPublisher(server.getEventPublisher());
    if (components.getSuccessHandler() != null) {
      processingFilter.setSuccessHandler(components.getSuccessHandler());
    }
    http.addFilterAfter(this.postProcess(processingFilter), OidcErrorResponseProcessingFilter.class);

    // User authentication and the authorization code ...
    //
    final UserAuthenticationFlow flow = server.getUserAuthenticationFlow();
    final OidcUserAuthenticationResponder responder = new OidcUserAuthenticationResponder(
        server.getClientRegistry(), this.activeSubjectGeneratorFactory, this.createAttributeReleaseManager(),
        this.getAttributeMapping(), this.authorizationCodeStore, responseSender, flow);
    responder.setCodeLifetime(this.authorizationCodeLifetime);
    responder.setCodeRetention(this.accessTokenLifetime);
    responder.setEventPublisher(server.getEventPublisher());
    final OidcUserAuthenticationProcessingFilter userAuthenticationFilter =
        new OidcUserAuthenticationProcessingFilter(this.authorizationRequestMatcher, flow, responder);
    http.addFilterAfter(this.postProcess(userAuthenticationFilter), OidcAuthnRequestProcessingFilter.class);
    final OidcResumedAuthenticationHandler resumedHandler =
        new OidcResumedAuthenticationHandler(flow, responder, responseSender);
    resumedHandler.setEventPublisher(server.getEventPublisher());
    this.resumedAuthenticationHandler = resumedHandler;

    // The token endpoint ...
    //
    final ClientAuthenticator clientAuthenticator = new ClientAuthenticator(server.getClientRegistry(),
        this.clientAuthenticationMethods, this.clientKeyResolver, this.clientAssertionReplayCache,
        this.getEndpointUrl(this.tokenEndpoint), this.getIssuer(), this.getClockSkew());
    clientAuthenticator.setMaxJwtAge(this.maxJwtAge);
    final TokenRequestProcessor tokenRequestProcessor = new TokenRequestProcessor(clientAuthenticator,
        this.authorizationCodeStore, this.accessTokenStore, idTokenBuilder);
    tokenRequestProcessor.setAccessTokenLifetime(this.accessTokenLifetime);
    tokenRequestProcessor.setSingleUseAccessTokens(this.singleUseAccessTokens);
    tokenRequestProcessor.setEventPublisher(server.getEventPublisher());
    http.addFilterBefore(this.postProcess(new OidcTokenEndpointFilter(this.tokenRequestMatcher, tokenRequestProcessor)),
        AbstractPreAuthenticatedProcessingFilter.class);

    // The UserInfo endpoint ...
    //
    final UserInfoRequestProcessor userInfoRequestProcessor = new UserInfoRequestProcessor(this.getIssuer(),
        this.accessTokenStore, server.getClientRegistry(), this.signingKeySelector,
        new ClientEncryption(this.clientKeyResolver));
    userInfoRequestProcessor.setSignUserInfo(this.signUserInfo);
    userInfoRequestProcessor.setEventPublisher(server.getEventPublisher());
    http.addFilterBefore(
        this.postProcess(new OidcUserInfoEndpointFilter(this.userInfoRequestMatcher, userInfoRequestProcessor)),
        AbstractPreAuthenticatedProcessingFilter.class);
  }

  /** {@inheritDoc} */
  @Override
  protected @Nullable ResumedAuthenticationHandler getResumedAuthenticationHandler() {
    return this.resumedAuthenticationHandler;
  }

  /**
   * The OpenID Provider needs at least one OpenID Connect client source: configured clients, a repository, a
   * federation backend or a backend of the application's own.
   */
  @Override
  protected boolean requiresClientRegistryBackend() {
    return true;
  }

  /** {@inheritDoc} */
  @Override
  protected @NonNull String getMissingClientRegistryBackendHint() {
    return "assign clients with authn-server.oidc.clients, resolve clients through OpenID Federation with "
        + "authn-server.oidc.federation.clients, or add a client registry backend (configured clients, a client "
        + "repository or one of the application's own) in an AuthnServerConfigurerAdapter";
  }

  /**
   * Gets the authentication context URIs that the authentication providers support.
   *
   * @return the authentication context URIs
   */
  @NonNull List<String> getSupportedAuthnContextUris() {
    return this.getServer().getAuthenticationProviders().stream()
        .map(UserAuthenticationProvider::getSupportedAuthnContextUris)
        .flatMap(Collection::stream)
        .distinct()
        .toList();
  }

  /** {@inheritDoc} */
  @Override
  protected @NonNull RequestMatcher getRequestMatcher() {
    return Objects.requireNonNull(this.requestMatcher, "The configurer has not been initialized");
  }

  /**
   * Gets the discovery endpoint configurer.
   *
   * @return the discovery endpoint configurer
   */
  @NonNull OidcDiscoveryEndpointConfigurer getDiscoveryEndpointConfigurer() {
    return this.discoveryEndpointConfigurer;
  }

  /**
   * Makes a post processing available to the sub-configurers.
   *
   * @param object the object
   * @param <O> the type
   * @return the processed object
   */
  <O> @NonNull O postProcessObject(final @NonNull O object) {
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
    if (!this.authorizationEndpoint.startsWith("/")) {
      throw new IllegalArgumentException(
          "Invalid OIDC authorization endpoint '%s' - it must begin with /".formatted(this.authorizationEndpoint));
    }
    if (!this.userInfoEndpoint.startsWith("/")) {
      throw new IllegalArgumentException(
          "Invalid OIDC UserInfo endpoint '%s' - it must begin with /".formatted(this.userInfoEndpoint));
    }
    if (!this.tokenEndpoint.startsWith("/")) {
      throw new IllegalArgumentException(
          "Invalid OIDC token endpoint '%s' - it must begin with /".formatted(this.tokenEndpoint));
    }
    assertPositive(this.authorizationCodeLifetime, "authorization code lifetime");
    assertPositive(this.accessTokenLifetime, "access token lifetime");
    assertPositive(this.idTokenLifetime, "ID token lifetime");
    if (this.maxJwtAge != null) {
      assertPositive(this.maxJwtAge, "maximum JWT age");
    }
    if (this.clientAuthenticationMethods.isEmpty()) {
      throw new IllegalArgumentException("At least one OIDC client authentication method must be enabled");
    }
    if (!ClientAuthenticator.SUPPORTED_METHODS.containsAll(this.clientAuthenticationMethods)) {
      throw new IllegalArgumentException("Unsupported OIDC client authentication method in %s - supported are %s"
          .formatted(this.clientAuthenticationMethods, ClientAuthenticator.SUPPORTED_METHODS));
    }
  }

  /**
   * Checks that a duration is positive.
   *
   * @param duration the duration
   * @param name the name of the value, for the error message
   */
  private static void assertPositive(final @NonNull Duration duration, final @NonNull String name) {
    if (duration.isNegative() || duration.isZero()) {
      throw new IllegalArgumentException("The OIDC %s must be positive".formatted(name));
    }
  }

}
