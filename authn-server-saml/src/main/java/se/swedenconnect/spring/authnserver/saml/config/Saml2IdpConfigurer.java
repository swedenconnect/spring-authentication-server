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
package se.swedenconnect.spring.authnserver.saml.config;

import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.opensaml.storage.ReplayCache;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import se.swedenconnect.opensaml.saml2.response.replay.MessageReplayChecker;
import se.swedenconnect.opensaml.saml2.response.replay.MessageReplayCheckerImpl;
import se.swedenconnect.opensaml.sweid.saml2.signservice.SADFactory;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.opensaml.OpenSamlCredential;
import se.swedenconnect.spring.authnserver.attributes.release.AttributeProducer;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.authentication.provider.UserAuthenticationProvider;
import se.swedenconnect.spring.authnserver.config.AbstractProtocolConfigurer;
import se.swedenconnect.spring.authnserver.config.AuthnServerConfigurer;
import se.swedenconnect.spring.authnserver.registry.ClientRegistryBackend;
import se.swedenconnect.spring.authnserver.saml.attributes.SamlAttributeMapping;
import se.swedenconnect.spring.authnserver.saml.attributes.release.SwedenConnectAttributeProducer;
import se.swedenconnect.spring.authnserver.saml.attributes.release.SwedenConnectAttributeReleaseVoter;
import se.swedenconnect.spring.authnserver.saml.attributes.requested.SamlRequestedAttributeResolver;
import se.swedenconnect.spring.authnserver.saml.authnrequest.AuthnContextResolver;
import se.swedenconnect.spring.authnserver.saml.authnrequest.DefaultSignMessageExtractor;
import se.swedenconnect.spring.authnserver.saml.authnrequest.Saml2AuthnRequestAuthenticationConverter;
import se.swedenconnect.spring.authnserver.saml.authnrequest.Saml2AuthnRequestAuthenticationProvider;
import se.swedenconnect.spring.authnserver.saml.authnrequest.validation.AssertionConsumerServiceValidator;
import se.swedenconnect.spring.authnserver.saml.authnrequest.validation.AuthnRequestEncryptCapabilitiesValidator;
import se.swedenconnect.spring.authnserver.saml.authnrequest.validation.AuthnRequestReplayValidator;
import se.swedenconnect.spring.authnserver.saml.authnrequest.validation.AuthnRequestSignatureValidator;
import se.swedenconnect.spring.authnserver.saml.authnrequest.validation.replay.InMemoryReplayCache;
import se.swedenconnect.spring.authnserver.saml.metadata.MetadataProviderFactory;
import se.swedenconnect.spring.authnserver.saml.metadata.MetadataSource;
import se.swedenconnect.spring.authnserver.saml.metadata.SamlMetadataBackend;
import se.swedenconnect.spring.authnserver.saml.nameid.DefaultNameIDGeneratorFactory;
import se.swedenconnect.spring.authnserver.saml.nameid.NameIDGeneratorFactory;
import se.swedenconnect.spring.authnserver.saml.response.Saml2AssertionBuilder;
import se.swedenconnect.spring.authnserver.saml.response.Saml2ResponseBuilder;
import se.swedenconnect.spring.authnserver.saml.response.Saml2ResponseSender;
import se.swedenconnect.spring.authnserver.saml.response.Saml2UserAuthenticationResponder;
import se.swedenconnect.spring.authnserver.saml.web.Saml2AuthnRequestProcessingFilter;
import se.swedenconnect.spring.authnserver.saml.web.Saml2ErrorResponseProcessingFilter;
import se.swedenconnect.spring.authnserver.saml.web.Saml2ResumedAuthenticationHandler;
import se.swedenconnect.spring.authnserver.saml.web.Saml2UserAuthenticationProcessingFilter;
import se.swedenconnect.spring.authnserver.web.ResumedAuthenticationHandler;
import se.swedenconnect.spring.authnserver.web.UserAuthenticationFlow;

/**
 * The protocol configurer for the SAML Identity Provider. Register it with the {@link AuthnServerConfigurer}.
 * <p>
 * The endpoints are given relative to the SAML path, which defaults to {@value #DEFAULT_PATH}, so the default endpoints
 * are {@code /saml2/redirect/authn}, {@code /saml2/post/authn} and {@code /saml2/metadata}.
 * </p>
 * <p>
 * The entity ID defaults to the base URL. A signing credential and an encryption credential are required. Each of them
 * falls back to the default credential when not assigned. The metadata signing credential falls back to the default
 * credential, and without either the metadata is not signed.
 * </p>
 * <p>
 * The Service Providers are found in the client registry. The configurer contributes a SAML metadata backend when
 * metadata sources or a metadata resolver have been assigned, and a SAML backend is required unless the client
 * registry has been assigned to the {@link AuthnServerConfigurer}.
 * </p>
 * <p>
 * The SAML attribute producers default to a {@link SwedenConnectAttributeProducer}, and the SAML attribute release
 * voters to a {@link SwedenConnectAttributeReleaseVoter}. Together with the shared defaults of the
 * {@link AuthnServerConfigurer}, this gives the release rules of the Swedish eID Framework.
 * </p>
 *
 * @author Martin Lindström
 */
public class Saml2IdpConfigurer extends AbstractProtocolConfigurer<Saml2IdpConfigurer> {

  /** The default SAML path, {@value}. */
  public static final String DEFAULT_PATH = "/saml2";

  /** The default endpoint for authentication requests sent with the redirect binding, {@value}. */
  public static final String DEFAULT_REDIRECT_AUTHN_ENDPOINT = "/redirect/authn";

  /** The default endpoint for authentication requests sent with the POST binding, {@value}. */
  public static final String DEFAULT_POST_AUTHN_ENDPOINT = "/post/authn";

  /** The default endpoint for publishing the IdP metadata, {@value}. */
  public static final String DEFAULT_METADATA_ENDPOINT = "/metadata";

  /** The default maximum age of a received message, 3 minutes. */
  public static final Duration DEFAULT_MAX_MESSAGE_AGE =
      Saml2AuthnRequestAuthenticationConverter.DEFAULT_MAX_MESSAGE_AGE;

  /** The default time that the IDs of received requests are kept for the replay check, 5 minutes. */
  public static final Duration DEFAULT_REPLAY_EXPIRATION = Duration.ofMinutes(5);

  /** The default context name of the replay cache, {@value}. */
  public static final String DEFAULT_REPLAY_CONTEXT = "idp-replay-checker";

  /** The SAML entity ID. */
  private String entityId;

  /** The base URL for Holder-of-key endpoints. */
  private String hokBaseUrl;

  /** Whether signed authentication requests are required. */
  private boolean requiresSignedRequests = true;

  /** The default credential. */
  private PkiCredential defaultCredential;

  /** The signing credential. */
  private PkiCredential signCredential;

  /** The future signing certificate. */
  private X509Certificate futureSignCertificate;

  /** The encryption credential. */
  private PkiCredential encryptCredential;

  /** The previous encryption credential. */
  private PkiCredential previousEncryptCredential;

  /** The metadata signing credential. */
  private PkiCredential metadataSignCredential;

  /** The redirect binding authentication endpoint. */
  private String redirectAuthnEndpoint = DEFAULT_REDIRECT_AUTHN_ENDPOINT;

  /** The POST binding authentication endpoint. */
  private String postAuthnEndpoint = DEFAULT_POST_AUTHN_ENDPOINT;

  /** The Holder-of-key redirect binding authentication endpoint. */
  private String hokRedirectAuthnEndpoint;

  /** The Holder-of-key POST binding authentication endpoint. */
  private String hokPostAuthnEndpoint;

  /** The metadata publishing endpoint. */
  private String metadataEndpoint = DEFAULT_METADATA_ENDPOINT;

  /** The factory for NameID generators, used for the NameID formats in the metadata. */
  private NameIDGeneratorFactory nameIdGeneratorFactory;

  /** The maximum age of a received message. */
  private Duration maxMessageAge = DEFAULT_MAX_MESSAGE_AGE;

  /** Whether assertions are encrypted. */
  private boolean encryptAssertions = true;

  /** How long an assertion is valid after it was issued. */
  private Duration assertionNotOnOrAfter = Saml2AssertionBuilder.DEFAULT_NOT_ON_OR_AFTER;

  /** How long before it was issued an assertion is valid. */
  private Duration assertionNotBefore = Saml2AssertionBuilder.DEFAULT_NOT_BEFORE;

  /** The mapping between generic attributes and SAML attributes. */
  private SamlAttributeMapping attributeMapping;

  /** The mapping for minimum comparison of requested authentication contexts. */
  private Map<String, List<String>> authnContextMinimumMapping;

  /** The mapping for better comparison of requested authentication contexts. */
  private Map<String, List<String>> authnContextBetterMapping;

  /** The mapping for maximum comparison of requested authentication contexts. */
  private Map<String, List<String>> authnContextMaximumMapping;

  /** The replay cache. */
  private ReplayCache replayCache;

  /** How long the IDs of received requests are kept for the replay check. */
  private Duration replayExpiration = DEFAULT_REPLAY_EXPIRATION;

  /** The context name of the replay cache. */
  private String replayContext = DEFAULT_REPLAY_CONTEXT;

  /** The SP metadata sources. */
  private List<MetadataSource> metadataSources;

  /** The SP metadata resolver. */
  private MetadataResolver metadataResolver;

  /** The SSL bundles for HTTPS metadata sources. */
  private SslBundles sslBundles;

  /** The configurer for the request processing components. */
  private final Saml2AuthnRequestProcessorConfigurer authnRequestProcessorConfigurer =
      new Saml2AuthnRequestProcessorConfigurer();

  /** The SP metadata backend, created at initialization. */
  private SamlMetadataBackend metadataBackend;

  /** The NameID generator factory that is used, assigned at initialization. */
  private NameIDGeneratorFactory activeNameIdGeneratorFactory;

  /** The matcher for the authentication endpoints. */
  private RequestMatcher authnRequestMatcher;

  /** The matcher for the Holder-of-key authentication endpoints. */
  private RequestMatcher holderOfKeyMatcher;

  /** The metadata endpoint configurer. */
  private final Saml2IdpMetadataEndpointConfigurer metadataEndpointConfigurer =
      new Saml2IdpMetadataEndpointConfigurer(this);

  /** The matcher for the SAML endpoints. */
  private RequestMatcher requestMatcher;

  /** Continues the SAML flow on the resume paths, created when the configurer is applied. */
  private ResumedAuthenticationHandler resumedAuthenticationHandler;

  /**
   * Constructor.
   */
  public Saml2IdpConfigurer() {
    super(DEFAULT_PATH);
    this.getAttributeProducers().add(new SwedenConnectAttributeProducer());
    this.getAttributeReleaseVoters().add(new SwedenConnectAttributeReleaseVoter());
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull AuthenticationProtocol getProtocol() {
    return AuthenticationProtocol.SAML;
  }

  /**
   * Assigns the SAML entity ID. Defaults to the base URL.
   *
   * @param entityId the entity ID, or {@code null} for the default
   * @return this configurer
   */
  public @NonNull Saml2IdpConfigurer entityId(final @Nullable String entityId) {
    this.entityId = entityId;
    return this;
  }

  /**
   * Gets the SAML entity ID, which is the base URL unless another entity ID has been assigned.
   *
   * @return the entity ID
   */
  public @NonNull String getEntityId() {
    return this.entityId != null ? this.entityId : Objects.requireNonNull(this.getServer().getBaseUrl());
  }

  /**
   * Assigns the base URL for the Holder-of-key endpoints, when they need another host or port than the base URL, for
   * client TLS. The Holder-of-key endpoints are this URL, the SAML path and the endpoint.
   *
   * @param hokBaseUrl the Holder-of-key base URL, or {@code null} to use the base URL
   * @return this configurer
   */
  public @NonNull Saml2IdpConfigurer hokBaseUrl(final @Nullable String hokBaseUrl) {
    this.hokBaseUrl = hokBaseUrl;
    return this;
  }

  /**
   * Gets the Holder-of-key base URL.
   *
   * @return the Holder-of-key base URL, or {@code null} if the base URL is used
   */
  public @Nullable String getHokBaseUrl() {
    return this.hokBaseUrl;
  }

  /**
   * Assigns whether the IdP requires signed authentication requests. Defaults to {@code true}.
   *
   * @param requiresSignedRequests whether signed authentication requests are required
   * @return this configurer
   */
  public @NonNull Saml2IdpConfigurer requiresSignedRequests(final boolean requiresSignedRequests) {
    this.requiresSignedRequests = requiresSignedRequests;
    return this;
  }

  /**
   * Tells whether the IdP requires signed authentication requests.
   *
   * @return {@code true} if signed requests are required and {@code false} otherwise
   */
  public boolean isRequiresSignedRequests() {
    return this.requiresSignedRequests;
  }

  /**
   * Assigns the default credential, used for signing, encryption and metadata signing when no specific credential has
   * been assigned for that use.
   *
   * @param defaultCredential the default credential
   * @return this configurer
   */
  public @NonNull Saml2IdpConfigurer defaultCredential(final @Nullable PkiCredential defaultCredential) {
    this.defaultCredential = defaultCredential;
    return this;
  }

  /**
   * Gets the default credential.
   *
   * @return the default credential, or {@code null} if none has been assigned
   */
  public @Nullable PkiCredential getDefaultCredential() {
    return this.defaultCredential;
  }

  /**
   * Assigns the credential that the IdP signs responses and assertions with.
   *
   * @param signCredential the signing credential
   * @return this configurer
   */
  public @NonNull Saml2IdpConfigurer signCredential(final @Nullable PkiCredential signCredential) {
    this.signCredential = signCredential;
    return this;
  }

  /**
   * Gets the signing credential, falling back to the default credential.
   *
   * @return the signing credential, or {@code null} if neither has been assigned
   */
  public @Nullable PkiCredential getSignCredential() {
    return this.signCredential != null ? this.signCredential : this.defaultCredential;
  }

  /**
   * Assigns the certificate that will be the future signing certificate. It is set before a key rollover so that it is
   * published in the metadata.
   *
   * @param futureSignCertificate the future signing certificate
   * @return this configurer
   */
  public @NonNull Saml2IdpConfigurer futureSignCertificate(final @Nullable X509Certificate futureSignCertificate) {
    this.futureSignCertificate = futureSignCertificate;
    return this;
  }

  /**
   * Gets the future signing certificate.
   *
   * @return the future signing certificate, or {@code null}
   */
  public @Nullable X509Certificate getFutureSignCertificate() {
    return this.futureSignCertificate;
  }

  /**
   * Assigns the encryption credential. Service Providers encrypt data for the IdP with its certificate, and the IdP
   * decrypts with it.
   *
   * @param encryptCredential the encryption credential
   * @return this configurer
   */
  public @NonNull Saml2IdpConfigurer encryptCredential(final @Nullable PkiCredential encryptCredential) {
    this.encryptCredential = encryptCredential;
    return this;
  }

  /**
   * Gets the encryption credential, falling back to the default credential.
   *
   * @return the encryption credential, or {@code null} if neither has been assigned
   */
  public @Nullable PkiCredential getEncryptCredential() {
    return this.encryptCredential != null ? this.encryptCredential : this.defaultCredential;
  }

  /**
   * Assigns the previous encryption credential, kept after a key rollover so that data encrypted for the old key can
   * still be decrypted.
   *
   * @param previousEncryptCredential the previous encryption credential
   * @return this configurer
   */
  public @NonNull Saml2IdpConfigurer previousEncryptCredential(
      final @Nullable PkiCredential previousEncryptCredential) {
    this.previousEncryptCredential = previousEncryptCredential;
    return this;
  }

  /**
   * Gets the previous encryption credential.
   *
   * @return the previous encryption credential, or {@code null}
   */
  public @Nullable PkiCredential getPreviousEncryptCredential() {
    return this.previousEncryptCredential;
  }

  /**
   * Assigns the credential that the IdP signs its metadata with.
   *
   * @param metadataSignCredential the metadata signing credential
   * @return this configurer
   */
  public @NonNull Saml2IdpConfigurer metadataSignCredential(final @Nullable PkiCredential metadataSignCredential) {
    this.metadataSignCredential = metadataSignCredential;
    return this;
  }

  /**
   * Gets the metadata signing credential, falling back to the default credential.
   *
   * @return the metadata signing credential, or {@code null} if the metadata is not signed
   */
  public @Nullable PkiCredential getMetadataSignCredential() {
    return this.metadataSignCredential != null ? this.metadataSignCredential : this.defaultCredential;
  }

  /**
   * Assigns the endpoint, relative to the SAML path, that receives authentication requests sent with the redirect
   * binding. Defaults to {@value #DEFAULT_REDIRECT_AUTHN_ENDPOINT}.
   *
   * @param endpoint the endpoint
   * @return this configurer
   */
  public @NonNull Saml2IdpConfigurer redirectAuthnEndpoint(final @NonNull String endpoint) {
    this.redirectAuthnEndpoint = Objects.requireNonNull(endpoint, "endpoint must not be null");
    return this;
  }

  /**
   * Gets the redirect binding authentication endpoint, relative to the SAML path.
   *
   * @return the endpoint
   */
  public @NonNull String getRedirectAuthnEndpoint() {
    return this.redirectAuthnEndpoint;
  }

  /**
   * Assigns the endpoint, relative to the SAML path, that receives authentication requests sent with the POST binding.
   * Defaults to {@value #DEFAULT_POST_AUTHN_ENDPOINT}.
   *
   * @param endpoint the endpoint
   * @return this configurer
   */
  public @NonNull Saml2IdpConfigurer postAuthnEndpoint(final @NonNull String endpoint) {
    this.postAuthnEndpoint = Objects.requireNonNull(endpoint, "endpoint must not be null");
    return this;
  }

  /**
   * Gets the POST binding authentication endpoint, relative to the SAML path.
   *
   * @return the endpoint
   */
  public @NonNull String getPostAuthnEndpoint() {
    return this.postAuthnEndpoint;
  }

  /**
   * Assigns the Holder-of-key endpoint, relative to the SAML path, that receives authentication requests sent with the
   * redirect binding. Holder-of-key is not offered unless assigned.
   *
   * @param endpoint the endpoint, or {@code null}
   * @return this configurer
   */
  public @NonNull Saml2IdpConfigurer hokRedirectAuthnEndpoint(final @Nullable String endpoint) {
    this.hokRedirectAuthnEndpoint = endpoint;
    return this;
  }

  /**
   * Gets the Holder-of-key redirect binding authentication endpoint, relative to the SAML path.
   *
   * @return the endpoint, or {@code null}
   */
  public @Nullable String getHokRedirectAuthnEndpoint() {
    return this.hokRedirectAuthnEndpoint;
  }

  /**
   * Assigns the Holder-of-key endpoint, relative to the SAML path, that receives authentication requests sent with the
   * POST binding. Holder-of-key is not offered unless assigned.
   *
   * @param endpoint the endpoint, or {@code null}
   * @return this configurer
   */
  public @NonNull Saml2IdpConfigurer hokPostAuthnEndpoint(final @Nullable String endpoint) {
    this.hokPostAuthnEndpoint = endpoint;
    return this;
  }

  /**
   * Gets the Holder-of-key POST binding authentication endpoint, relative to the SAML path.
   *
   * @return the endpoint, or {@code null}
   */
  public @Nullable String getHokPostAuthnEndpoint() {
    return this.hokPostAuthnEndpoint;
  }

  /**
   * Assigns the endpoint, relative to the SAML path, where the IdP metadata is published. Defaults to
   * {@value #DEFAULT_METADATA_ENDPOINT}.
   *
   * @param endpoint the endpoint
   * @return this configurer
   */
  public @NonNull Saml2IdpConfigurer metadataEndpoint(final @NonNull String endpoint) {
    this.metadataEndpoint = Objects.requireNonNull(endpoint, "endpoint must not be null");
    return this;
  }

  /**
   * Gets the metadata publishing endpoint, relative to the SAML path.
   *
   * @return the endpoint
   */
  public @NonNull String getMetadataEndpoint() {
    return this.metadataEndpoint;
  }

  /**
   * Assigns the factory for {@code NameID} generators. It checks the {@code NameIDPolicy} of each request, and its
   * supported formats are declared in the metadata. Without a factory, a {@link DefaultNameIDGeneratorFactory} with the
   * subject identifier secret and hash algorithm is used.
   *
   * @param nameIdGeneratorFactory the factory
   * @return this configurer
   */
  public @NonNull Saml2IdpConfigurer nameIdGeneratorFactory(
      final @Nullable NameIDGeneratorFactory nameIdGeneratorFactory) {
    this.nameIdGeneratorFactory = nameIdGeneratorFactory;
    return this;
  }

  /**
   * Gets the factory for {@code NameID} generators.
   *
   * @return the factory, or {@code null}
   */
  public @Nullable NameIDGeneratorFactory getNameIdGeneratorFactory() {
    return this.nameIdGeneratorFactory;
  }

  /**
   * Assigns the maximum age of a received authentication request. Defaults to {@link #DEFAULT_MAX_MESSAGE_AGE}.
   *
   * @param maxMessageAge the maximum age
   * @return this configurer
   */
  public @NonNull Saml2IdpConfigurer maxMessageAge(final @NonNull Duration maxMessageAge) {
    this.maxMessageAge = Objects.requireNonNull(maxMessageAge, "maxMessageAge must not be null");
    return this;
  }

  /**
   * Gets the maximum age of a received authentication request.
   *
   * @return the maximum age
   */
  public @NonNull Duration getMaxMessageAge() {
    return this.maxMessageAge;
  }

  /**
   * Assigns whether assertions are encrypted. Defaults to {@code true}. When they are, a request from a Service
   * Provider whose metadata has no encryption key is rejected.
   *
   * @param encryptAssertions whether assertions are encrypted
   * @return this configurer
   */
  public @NonNull Saml2IdpConfigurer encryptAssertions(final boolean encryptAssertions) {
    this.encryptAssertions = encryptAssertions;
    return this;
  }

  /**
   * Tells whether assertions are encrypted.
   *
   * @return {@code true} if assertions are encrypted and {@code false} otherwise
   */
  public boolean isEncryptAssertions() {
    return this.encryptAssertions;
  }

  /**
   * Assigns how long an assertion is valid after it was issued, which gives {@code NotOnOrAfter} of the conditions and
   * of the subject confirmation. Defaults to {@link Saml2AssertionBuilder#DEFAULT_NOT_ON_OR_AFTER}.
   *
   * @param notOnOrAfter the duration
   * @return this configurer
   */
  public @NonNull Saml2IdpConfigurer assertionNotOnOrAfter(final @NonNull Duration notOnOrAfter) {
    this.assertionNotOnOrAfter = Objects.requireNonNull(notOnOrAfter, "notOnOrAfter must not be null");
    return this;
  }

  /**
   * Assigns how long before it was issued an assertion is valid, which gives {@code NotBefore} of the conditions.
   * Defaults to {@link Saml2AssertionBuilder#DEFAULT_NOT_BEFORE}.
   *
   * @param notBefore the duration
   * @return this configurer
   */
  public @NonNull Saml2IdpConfigurer assertionNotBefore(final @NonNull Duration notBefore) {
    this.assertionNotBefore = Objects.requireNonNull(notBefore, "notBefore must not be null");
    return this;
  }

  /**
   * Gets how long an assertion is valid after it was issued.
   *
   * @return the duration
   */
  public @NonNull Duration getAssertionNotOnOrAfter() {
    return this.assertionNotOnOrAfter;
  }

  /**
   * Gets how long before it was issued an assertion is valid.
   *
   * @return the duration
   */
  public @NonNull Duration getAssertionNotBefore() {
    return this.assertionNotBefore;
  }

  /**
   * Assigns the mapping between generic attributes and SAML attributes, used when the released attributes are put in
   * the assertion and when the requested attributes are worked out. Defaults to a {@link SamlAttributeMapping} with
   * the built-in mappers.
   *
   * @param attributeMapping the mapping, or {@code null} for the default
   * @return this configurer
   */
  public @NonNull Saml2IdpConfigurer attributeMapping(final @Nullable SamlAttributeMapping attributeMapping) {
    this.attributeMapping = attributeMapping;
    return this;
  }

  /**
   * Gets the mapping between generic attributes and SAML attributes: the assigned one, or one with the built-in
   * mappers. The default is created once.
   *
   * @return the mapping
   */
  public @NonNull SamlAttributeMapping getAttributeMapping() {
    if (this.attributeMapping == null) {
      this.attributeMapping = new SamlAttributeMapping();
    }
    return this.attributeMapping;
  }

  /**
   * Assigns the mappings for the {@code minimum}, {@code better} and {@code maximum} comparisons of requested
   * authentication contexts, see {@link AuthnContextResolver}. A comparison without a mapping is not supported.
   *
   * @param minimumMapping the mapping for minimum comparison, or {@code null}
   * @param betterMapping the mapping for better comparison, or {@code null}
   * @param maximumMapping the mapping for maximum comparison, or {@code null}
   * @return this configurer
   */
  public @NonNull Saml2IdpConfigurer authnContextMappings(final @Nullable Map<String, List<String>> minimumMapping,
      final @Nullable Map<String, List<String>> betterMapping,
      final @Nullable Map<String, List<String>> maximumMapping) {
    this.authnContextMinimumMapping = minimumMapping;
    this.authnContextBetterMapping = betterMapping;
    this.authnContextMaximumMapping = maximumMapping;
    return this;
  }

  /**
   * Assigns the store for the replay check. The default is an {@link InMemoryReplayCache}, which only protects the
   * node it runs on.
   *
   * @param replayCache the replay cache
   * @return this configurer
   */
  public @NonNull Saml2IdpConfigurer replayCache(final @Nullable ReplayCache replayCache) {
    this.replayCache = replayCache;
    return this;
  }

  /**
   * Assigns how long the IDs of received requests are kept for the replay check. Defaults to
   * {@link #DEFAULT_REPLAY_EXPIRATION}.
   *
   * @param replayExpiration the expiration time
   * @return this configurer
   */
  public @NonNull Saml2IdpConfigurer replayExpiration(final @NonNull Duration replayExpiration) {
    this.replayExpiration = Objects.requireNonNull(replayExpiration, "replayExpiration must not be null");
    return this;
  }

  /**
   * Assigns the context name under which the replay cache stores the IDs. Defaults to
   * {@value #DEFAULT_REPLAY_CONTEXT}.
   *
   * @param replayContext the context name
   * @return this configurer
   */
  public @NonNull Saml2IdpConfigurer replayContext(final @NonNull String replayContext) {
    this.replayContext = Objects.requireNonNull(replayContext, "replayContext must not be null");
    return this;
  }

  /**
   * Assigns the sources of Service Provider metadata. A SAML metadata backend for the client registry is created from
   * them.
   *
   * @param metadataSources the metadata sources
   * @return this configurer
   */
  public @NonNull Saml2IdpConfigurer metadataSources(final @Nullable List<MetadataSource> metadataSources) {
    this.metadataSources = metadataSources;
    return this;
  }

  /**
   * Assigns the SSL bundles that HTTPS metadata sources refer to.
   *
   * @param sslBundles the SSL bundles
   * @return this configurer
   */
  public @NonNull Saml2IdpConfigurer sslBundles(final @Nullable SslBundles sslBundles) {
    this.sslBundles = sslBundles;
    return this;
  }

  /**
   * Assigns a metadata resolver for Service Provider metadata, as an alternative to
   * {@link #metadataSources(List)}. A SAML metadata backend for the client registry is created from it.
   *
   * @param metadataResolver the metadata resolver
   * @return this configurer
   */
  public @NonNull Saml2IdpConfigurer metadataResolver(final @Nullable MetadataResolver metadataResolver) {
    this.metadataResolver = metadataResolver;
    return this;
  }

  /**
   * Customizes the components that process authentication requests and send error responses.
   *
   * @param customizer the customizer
   * @return this configurer
   */
  public @NonNull Saml2IdpConfigurer authnRequestProcessor(
      final @NonNull Customizer<Saml2AuthnRequestProcessorConfigurer> customizer) {
    customizer.customize(this.authnRequestProcessorConfigurer);
    return this;
  }

  /**
   * Customizes the metadata that the IdP publishes.
   *
   * @param customizer the customizer
   * @return this configurer
   */
  public @NonNull Saml2IdpConfigurer idpMetadataEndpoint(
      final @NonNull Customizer<Saml2IdpMetadataEndpointConfigurer> customizer) {
    customizer.customize(this.metadataEndpointConfigurer);
    return this;
  }

  /**
   * Gets the URL of an endpoint that is served on the Holder-of-key base URL.
   *
   * @param endpoint the endpoint, relative to the SAML path
   * @return the URL
   */
  public @NonNull String getHokEndpointUrl(final @NonNull String endpoint) {
    return this.hokBaseUrl != null ? this.hokBaseUrl + this.getEndpointPath(endpoint) : this.getEndpointUrl(endpoint);
  }

  /** {@inheritDoc} */
  @Override
  protected void init(final @NonNull HttpSecurity http) {
    this.validate();

    final List<RequestMatcher> authnMatchers = new ArrayList<>();
    authnMatchers.add(PathPatternRequestMatcher.pathPattern(
        HttpMethod.GET, this.getEndpointPath(this.redirectAuthnEndpoint)));
    authnMatchers.add(PathPatternRequestMatcher.pathPattern(
        HttpMethod.POST, this.getEndpointPath(this.postAuthnEndpoint)));
    final List<RequestMatcher> hokMatchers = new ArrayList<>();
    if (this.hokRedirectAuthnEndpoint != null) {
      hokMatchers.add(PathPatternRequestMatcher.pathPattern(
          HttpMethod.GET, this.getEndpointPath(this.hokRedirectAuthnEndpoint)));
    }
    if (this.hokPostAuthnEndpoint != null) {
      hokMatchers.add(PathPatternRequestMatcher.pathPattern(
          HttpMethod.POST, this.getEndpointPath(this.hokPostAuthnEndpoint)));
    }
    authnMatchers.addAll(hokMatchers);
    this.authnRequestMatcher = new OrRequestMatcher(authnMatchers);
    this.holderOfKeyMatcher = hokMatchers.isEmpty() ? request -> false : new OrRequestMatcher(hokMatchers);

    this.metadataEndpointConfigurer.init();
    this.requestMatcher = new OrRequestMatcher(this.authnRequestMatcher,
        this.metadataEndpointConfigurer.getRequestMatcher());

    if (this.metadataResolver != null) {
      this.metadataBackend = new SamlMetadataBackend(this.metadataResolver);
    }
    else if (this.metadataSources != null && !this.metadataSources.isEmpty()) {
      this.metadataBackend = new SamlMetadataBackend(
          MetadataProviderFactory.createMetadataResolver(this.metadataSources, this.sslBundles));
    }

    if (this.nameIdGeneratorFactory != null) {
      this.activeNameIdGeneratorFactory = this.nameIdGeneratorFactory;
    }
    else {
      final DefaultNameIDGeneratorFactory factory = new DefaultNameIDGeneratorFactory(this.getEntityId());
      factory.setSecret(this.getSubjectIdentifierSecret());
      factory.setHashAlgorithm(this.getSubjectIdentifierHashAlgorithm());
      this.activeNameIdGeneratorFactory = factory;
    }
  }

  /** {@inheritDoc} */
  @Override
  protected void configure(final @NonNull HttpSecurity http) {
    this.metadataEndpointConfigurer.configure(http);

    final Saml2AuthnRequestProcessorConfigurer components = this.authnRequestProcessorConfigurer;
    final AuthnServerConfigurer server = this.getServer();

    // Error responses ...
    //
    final Saml2ResponseBuilder responseBuilder =
        new Saml2ResponseBuilder(this.getEntityId(), Objects.requireNonNull(this.getSignCredential()));
    responseBuilder.setMessageSource(components.getMessageSource());
    if (components.getResponseCustomizer() != null) {
      responseBuilder.setResponseCustomizer(components.getResponseCustomizer());
    }
    final Saml2ResponseSender responseSender = new Saml2ResponseSender();
    if (components.getResponsePage() != null) {
      responseSender.setResponsePage(components.getResponsePage());
    }
    responseBuilder.setEncryptAssertions(this.encryptAssertions);
    final Saml2ErrorResponseProcessingFilter errorFilter =
        new Saml2ErrorResponseProcessingFilter(this.authnRequestMatcher, responseBuilder, responseSender);
    http.addFilterAfter(this.postProcess(errorFilter), ExceptionTranslationFilter.class);

    // Request processing ...
    //
    final Saml2AuthnRequestAuthenticationConverter converter = new Saml2AuthnRequestAuthenticationConverter(
        server.getClientRegistry(), this.holderOfKeyMatcher, this.getClockSkew(), this.maxMessageAge);

    final AuthnContextResolver authnContextResolver = new AuthnContextResolver();
    authnContextResolver.setMinimumMapping(this.authnContextMinimumMapping);
    authnContextResolver.setBetterMapping(this.authnContextBetterMapping);
    authnContextResolver.setMaximumMapping(this.authnContextMaximumMapping);

    final Saml2AuthnRequestAuthenticationProvider provider = new Saml2AuthnRequestAuthenticationProvider(
        new AuthnRequestReplayValidator(this.getMessageReplayChecker()),
        Objects.requireNonNullElseGet(components.getAssertionConsumerServiceValidator(),
            AssertionConsumerServiceValidator::new),
        new AuthnRequestSignatureValidator(this.requiresSignedRequests),
        new AuthnRequestEncryptCapabilitiesValidator(this.encryptAssertions),
        server.getClientRegistry(),
        server.getRequesterAcceptance(),
        this.activeNameIdGeneratorFactory,
        Objects.requireNonNullElseGet(components.getRequestedAttributeResolver(),
            () -> new SamlRequestedAttributeResolver(this.getAttributeMapping(),
                SamlRequestedAttributeResolver.getDefaultProcessors(this.getDeclaredEntityCategories()))),
        authnContextResolver,
        Objects.requireNonNullElseGet(components.getSignMessageExtractor(),
            () -> new DefaultSignMessageExtractor(this.getEntityId(), this.getDecryptionCredentials())),
        this.isSupportsUserMessage());

    final Saml2AuthnRequestProcessingFilter processingFilter =
        new Saml2AuthnRequestProcessingFilter(this.authnRequestMatcher, converter, provider);
    if (components.getSuccessHandler() != null) {
      processingFilter.setSuccessHandler(components.getSuccessHandler());
    }
    http.addFilterAfter(this.postProcess(processingFilter), Saml2ErrorResponseProcessingFilter.class);

    // User authentication and response ...
    //
    for (final AttributeProducer producer : this.getAttributeProducers()) {
      if (producer instanceof final SwedenConnectAttributeProducer scProducer && scProducer.getSadFactory() == null) {
        scProducer.setSadFactory(new SADFactory(this.getEntityId(),
            new OpenSamlCredential(Objects.requireNonNull(this.getSignCredential()))));
      }
    }
    final Saml2AssertionBuilder assertionBuilder = new Saml2AssertionBuilder(this.getEntityId(),
        Objects.requireNonNull(this.getSignCredential()), this.createAttributeReleaseManager(),
        this.getAttributeMapping());
    assertionBuilder.setNotOnOrAfter(this.assertionNotOnOrAfter);
    assertionBuilder.setNotBefore(this.assertionNotBefore);
    assertionBuilder.setAssertionCustomizer(components.getAssertionCustomizer());

    final UserAuthenticationFlow flow = server.getUserAuthenticationFlow();
    final Saml2UserAuthenticationResponder responder =
        new Saml2UserAuthenticationResponder(assertionBuilder, responseBuilder, responseSender, flow);
    final Saml2UserAuthenticationProcessingFilter userAuthenticationFilter =
        new Saml2UserAuthenticationProcessingFilter(this.authnRequestMatcher, flow, responder);
    http.addFilterAfter(this.postProcess(userAuthenticationFilter), Saml2AuthnRequestProcessingFilter.class);

    this.resumedAuthenticationHandler = new Saml2ResumedAuthenticationHandler(flow, responder);
  }

  /** {@inheritDoc} */
  @Override
  protected @Nullable ResumedAuthenticationHandler getResumedAuthenticationHandler() {
    return this.resumedAuthenticationHandler;
  }

  /** {@inheritDoc} */
  @Override
  protected @NonNull List<ClientRegistryBackend> getClientRegistryBackends() {
    return this.metadataBackend != null ? List.of(this.metadataBackend) : List.of();
  }

  /** {@inheritDoc} */
  @Override
  protected boolean requiresClientRegistryBackend() {
    return true;
  }

  /** {@inheritDoc} */
  @Override
  protected @NonNull String getMissingClientRegistryBackendHint() {
    return "assign SP metadata sources (authn-server.saml.metadata-providers) or a metadata resolver";
  }

  /**
   * Gets the NameID generator factory that is used: the assigned one, or a {@link DefaultNameIDGeneratorFactory}.
   * Available after initialization.
   *
   * @return the factory
   */
  @NonNull NameIDGeneratorFactory getActiveNameIdGeneratorFactory() {
    return Objects.requireNonNull(this.activeNameIdGeneratorFactory, "The configurer has not been initialized");
  }

  /**
   * Gets the replay checker: the assigned one, or one built from the replay cache and the replay values.
   *
   * @return the replay checker
   */
  private @NonNull MessageReplayChecker getMessageReplayChecker() {
    if (this.authnRequestProcessorConfigurer.getMessageReplayChecker() != null) {
      return this.authnRequestProcessorConfigurer.getMessageReplayChecker();
    }
    final MessageReplayCheckerImpl checker = new MessageReplayCheckerImpl(
        this.replayCache != null ? this.replayCache : new InMemoryReplayCache(), this.replayContext);
    checker.setReplayCacheExpiration(this.replayExpiration.toMillis());
    return checker;
  }

  /**
   * Gets the entity categories that the authentication providers declare.
   *
   * @return the entity categories
   */
  private @NonNull List<String> getDeclaredEntityCategories() {
    return this.getServer().getAuthenticationProviders().stream()
        .map(UserAuthenticationProvider::getEntityCategories)
        .flatMap(Collection::stream)
        .distinct()
        .toList();
  }

  /**
   * Gets the credentials for decrypting encrypted messages: the encryption credential, and the previous one.
   *
   * @return the decryption credentials
   */
  private @NonNull List<PkiCredential> getDecryptionCredentials() {
    final List<PkiCredential> credentials = new ArrayList<>();
    if (this.getEncryptCredential() != null) {
      credentials.add(this.getEncryptCredential());
      if (this.previousEncryptCredential != null) {
        credentials.add(this.previousEncryptCredential);
      }
    }
    return credentials;
  }

  /** {@inheritDoc} */
  @Override
  protected @NonNull RequestMatcher getRequestMatcher() {
    return Objects.requireNonNull(this.requestMatcher, "The configurer has not been initialized");
  }

  /**
   * Gets the signing credential that has been assigned, without falling back to the default credential.
   *
   * @return the signing credential, or {@code null}
   */
  @Nullable PkiCredential getAssignedSignCredential() {
    return this.signCredential;
  }

  /**
   * Gets the encryption credential that has been assigned, without falling back to the default credential.
   *
   * @return the encryption credential, or {@code null}
   */
  @Nullable PkiCredential getAssignedEncryptCredential() {
    return this.encryptCredential;
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
   * Checks that the values required by the SAML Identity Provider are set and valid.
   *
   * @throws IllegalArgumentException if a value is missing or invalid
   */
  private void validate() {
    if (this.entityId != null && this.entityId.isBlank()) {
      throw new IllegalArgumentException("SAML entity ID must not be blank");
    }
    if (this.hokBaseUrl != null) {
      AuthnServerConfigurer.assertBaseUrl(this.hokBaseUrl, "SAML Holder-of-key base URL");
    }
    if (this.getSignCredential() == null) {
      throw new IllegalArgumentException("Missing SAML signing credential - assign a signing credential or a default "
          + "credential (authn-server.saml.credentials.sign or authn-server.saml.credentials.default-credential)");
    }
    if (this.getEncryptCredential() == null) {
      throw new IllegalArgumentException("Missing SAML encryption credential - assign an encryption credential or a "
          + "default credential (authn-server.saml.credentials.encrypt or "
          + "authn-server.saml.credentials.default-credential)");
    }
    if (this.maxMessageAge.isNegative() || this.maxMessageAge.isZero()) {
      throw new IllegalArgumentException("SAML maximum message age must be positive");
    }
    if (this.assertionNotOnOrAfter.isNegative() || this.assertionNotOnOrAfter.isZero()) {
      throw new IllegalArgumentException("SAML assertion not-after duration must be positive");
    }
    if (this.assertionNotBefore.isNegative()) {
      throw new IllegalArgumentException("SAML assertion not-before duration must not be negative");
    }
    if (this.replayExpiration.isNegative() || this.replayExpiration.isZero()) {
      throw new IllegalArgumentException("SAML replay expiration must be positive");
    }
    assertEndpoint(this.redirectAuthnEndpoint, "redirect authn");
    assertEndpoint(this.postAuthnEndpoint, "post authn");
    assertEndpoint(this.metadataEndpoint, "metadata");
    if (this.hokRedirectAuthnEndpoint != null) {
      assertEndpoint(this.hokRedirectAuthnEndpoint, "Holder-of-key redirect authn");
    }
    if (this.hokPostAuthnEndpoint != null) {
      assertEndpoint(this.hokPostAuthnEndpoint, "Holder-of-key post authn");
    }
  }

  /**
   * Checks that an endpoint begins with a {@code /}.
   *
   * @param endpoint the endpoint
   * @param name the name of the endpoint, for the error message
   */
  private static void assertEndpoint(final @NonNull String endpoint, final @NonNull String name) {
    if (!endpoint.startsWith("/")) {
      throw new IllegalArgumentException(
          "Invalid SAML %s endpoint '%s' - it must begin with /".formatted(name, endpoint));
    }
  }

}
