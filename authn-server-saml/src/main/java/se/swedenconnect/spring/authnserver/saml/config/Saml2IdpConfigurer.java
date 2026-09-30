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

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.config.AbstractProtocolConfigurer;
import se.swedenconnect.spring.authnserver.config.AuthnServerConfigurer;
import se.swedenconnect.spring.authnserver.saml.nameid.NameIDGeneratorFactory;

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

  /** The metadata endpoint configurer. */
  private final Saml2IdpMetadataEndpointConfigurer metadataEndpointConfigurer =
      new Saml2IdpMetadataEndpointConfigurer(this);

  /** The matcher for the SAML endpoints. */
  private RequestMatcher requestMatcher;

  /**
   * Constructor.
   */
  public Saml2IdpConfigurer() {
    super(DEFAULT_PATH);
  }

  /** {@inheritDoc} */
  @Override
  public @Nonnull AuthenticationProtocol getProtocol() {
    return AuthenticationProtocol.SAML;
  }

  /**
   * Assigns the SAML entity ID. Defaults to the base URL.
   *
   * @param entityId the entity ID, or {@code null} for the default
   * @return this configurer
   */
  public @Nonnull Saml2IdpConfigurer entityId(final @Nullable String entityId) {
    this.entityId = entityId;
    return this;
  }

  /**
   * Gets the SAML entity ID, which is the base URL unless another entity ID has been assigned.
   *
   * @return the entity ID
   */
  public @Nonnull String getEntityId() {
    return this.entityId != null ? this.entityId : Objects.requireNonNull(this.getServer().getBaseUrl());
  }

  /**
   * Assigns the base URL for the Holder-of-key endpoints, when they need another host or port than the base URL, for
   * client TLS. The Holder-of-key endpoints are this URL, the SAML path and the endpoint.
   *
   * @param hokBaseUrl the Holder-of-key base URL, or {@code null} to use the base URL
   * @return this configurer
   */
  public @Nonnull Saml2IdpConfigurer hokBaseUrl(final @Nullable String hokBaseUrl) {
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
  public @Nonnull Saml2IdpConfigurer requiresSignedRequests(final boolean requiresSignedRequests) {
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
  public @Nonnull Saml2IdpConfigurer defaultCredential(final @Nullable PkiCredential defaultCredential) {
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
  public @Nonnull Saml2IdpConfigurer signCredential(final @Nullable PkiCredential signCredential) {
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
  public @Nonnull Saml2IdpConfigurer futureSignCertificate(final @Nullable X509Certificate futureSignCertificate) {
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
  public @Nonnull Saml2IdpConfigurer encryptCredential(final @Nullable PkiCredential encryptCredential) {
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
  public @Nonnull Saml2IdpConfigurer previousEncryptCredential(
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
  public @Nonnull Saml2IdpConfigurer metadataSignCredential(final @Nullable PkiCredential metadataSignCredential) {
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
  public @Nonnull Saml2IdpConfigurer redirectAuthnEndpoint(final @Nonnull String endpoint) {
    this.redirectAuthnEndpoint = Objects.requireNonNull(endpoint, "endpoint must not be null");
    return this;
  }

  /**
   * Gets the redirect binding authentication endpoint, relative to the SAML path.
   *
   * @return the endpoint
   */
  public @Nonnull String getRedirectAuthnEndpoint() {
    return this.redirectAuthnEndpoint;
  }

  /**
   * Assigns the endpoint, relative to the SAML path, that receives authentication requests sent with the POST binding.
   * Defaults to {@value #DEFAULT_POST_AUTHN_ENDPOINT}.
   *
   * @param endpoint the endpoint
   * @return this configurer
   */
  public @Nonnull Saml2IdpConfigurer postAuthnEndpoint(final @Nonnull String endpoint) {
    this.postAuthnEndpoint = Objects.requireNonNull(endpoint, "endpoint must not be null");
    return this;
  }

  /**
   * Gets the POST binding authentication endpoint, relative to the SAML path.
   *
   * @return the endpoint
   */
  public @Nonnull String getPostAuthnEndpoint() {
    return this.postAuthnEndpoint;
  }

  /**
   * Assigns the Holder-of-key endpoint, relative to the SAML path, that receives authentication requests sent with the
   * redirect binding. Holder-of-key is not offered unless assigned.
   *
   * @param endpoint the endpoint, or {@code null}
   * @return this configurer
   */
  public @Nonnull Saml2IdpConfigurer hokRedirectAuthnEndpoint(final @Nullable String endpoint) {
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
  public @Nonnull Saml2IdpConfigurer hokPostAuthnEndpoint(final @Nullable String endpoint) {
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
  public @Nonnull Saml2IdpConfigurer metadataEndpoint(final @Nonnull String endpoint) {
    this.metadataEndpoint = Objects.requireNonNull(endpoint, "endpoint must not be null");
    return this;
  }

  /**
   * Gets the metadata publishing endpoint, relative to the SAML path.
   *
   * @return the endpoint
   */
  public @Nonnull String getMetadataEndpoint() {
    return this.metadataEndpoint;
  }

  /**
   * Assigns the factory for {@code NameID} generators. Its supported formats are declared in the metadata. Without a
   * factory, the persistent and transient formats are declared.
   *
   * @param nameIdGeneratorFactory the factory
   * @return this configurer
   */
  public @Nonnull Saml2IdpConfigurer nameIdGeneratorFactory(
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
   * Customizes the metadata that the IdP publishes.
   *
   * @param customizer the customizer
   * @return this configurer
   */
  public @Nonnull Saml2IdpConfigurer idpMetadataEndpoint(
      final @Nonnull Customizer<Saml2IdpMetadataEndpointConfigurer> customizer) {
    customizer.customize(this.metadataEndpointConfigurer);
    return this;
  }

  /**
   * Gets the URL of an endpoint that is served on the Holder-of-key base URL.
   *
   * @param endpoint the endpoint, relative to the SAML path
   * @return the URL
   */
  public @Nonnull String getHokEndpointUrl(final @Nonnull String endpoint) {
    return this.hokBaseUrl != null ? this.hokBaseUrl + this.getEndpointPath(endpoint) : this.getEndpointUrl(endpoint);
  }

  /** {@inheritDoc} */
  @Override
  protected void init(final @Nonnull HttpSecurity http) {
    this.validate();

    final List<RequestMatcher> matchers = new ArrayList<>();
    matchers.add(PathPatternRequestMatcher.pathPattern(
        HttpMethod.GET, this.getEndpointPath(this.redirectAuthnEndpoint)));
    matchers.add(PathPatternRequestMatcher.pathPattern(
        HttpMethod.POST, this.getEndpointPath(this.postAuthnEndpoint)));
    if (this.hokRedirectAuthnEndpoint != null) {
      matchers.add(PathPatternRequestMatcher.pathPattern(
          HttpMethod.GET, this.getEndpointPath(this.hokRedirectAuthnEndpoint)));
    }
    if (this.hokPostAuthnEndpoint != null) {
      matchers.add(PathPatternRequestMatcher.pathPattern(
          HttpMethod.POST, this.getEndpointPath(this.hokPostAuthnEndpoint)));
    }
    this.metadataEndpointConfigurer.init();
    matchers.add(this.metadataEndpointConfigurer.getRequestMatcher());

    this.requestMatcher = new OrRequestMatcher(matchers);
  }

  /** {@inheritDoc} */
  @Override
  protected void configure(final @Nonnull HttpSecurity http) {
    this.metadataEndpointConfigurer.configure(http);
  }

  /** {@inheritDoc} */
  @Override
  protected @Nonnull RequestMatcher getRequestMatcher() {
    return Objects.requireNonNull(this.requestMatcher, "The configurer has not been initialized");
  }

  /**
   * Gets the signing credential that has been assigned, without falling back to the default credential.
   *
   * @return the signing credential, or {@code null}
   */
  @Nullable
  PkiCredential getAssignedSignCredential() {
    return this.signCredential;
  }

  /**
   * Gets the encryption credential that has been assigned, without falling back to the default credential.
   *
   * @return the encryption credential, or {@code null}
   */
  @Nullable
  PkiCredential getAssignedEncryptCredential() {
    return this.encryptCredential;
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
  private static void assertEndpoint(final @Nonnull String endpoint, final @Nonnull String name) {
    if (!endpoint.startsWith("/")) {
      throw new IllegalArgumentException("Invalid SAML %s endpoint '%s' - it must begin with /".formatted(name, endpoint));
    }
  }

}
