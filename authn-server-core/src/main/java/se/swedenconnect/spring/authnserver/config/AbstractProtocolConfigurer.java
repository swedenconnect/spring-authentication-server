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
package se.swedenconnect.spring.authnserver.config;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;

import java.time.Duration;
import java.util.Objects;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.util.matcher.RequestMatcher;

import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.sso.SsoPolicy;

/**
 * Base class for the configurer of one protocol, such as the SAML Identity Provider or the OpenID Provider. A protocol
 * configurer is registered with the {@link AuthnServerConfigurer}, which applies it in the server's filter chain.
 * <p>
 * The configurer holds the protocol path, under which the protocol's endpoints are placed, and the values that the
 * protocol may override from the {@link AuthnServerConfigurer}. A value that has not been assigned here is taken from
 * the {@link AuthnServerConfigurer}.
 * </p>
 * <p>
 * An endpoint is normally given relative to the protocol path, and its URL is the base URL, the protocol path and the
 * endpoint. A protocol that needs an endpoint directly under the base URL uses
 * {@link AuthnServerConfigurer#getBaseUrl()} for it.
 * </p>
 *
 * @param <T> the type of the configurer
 * @author Martin Lindström
 */
public abstract class AbstractProtocolConfigurer<T extends AbstractProtocolConfigurer<T>> {

  /** The protocol path. */
  private String path;

  /** The shared configurer that this configurer has been registered with. */
  private AuthnServerConfigurer server;

  /** The protocol's single sign-on policy, or {@code null} to use the shared one. */
  private SsoPolicy ssoPolicy;

  /** The protocol's clock skew, or {@code null} to use the shared one. */
  private Duration clockSkew;

  /** Whether the protocol supports user messages, or {@code null} to use the shared setting. */
  private Boolean supportsUserMessage;

  /** The protocol's subject identifier secret, or {@code null} to use the shared one. */
  private byte[] subjectIdentifierSecret;

  /** The protocol's subject identifier hash algorithm, or {@code null} to use the shared one. */
  private String subjectIdentifierHashAlgorithm;

  /**
   * Constructor.
   *
   * @param defaultPath the default protocol path
   */
  protected AbstractProtocolConfigurer(final @Nonnull String defaultPath) {
    this.path = Objects.requireNonNull(defaultPath, "defaultPath must not be null");
  }

  /**
   * Gets the protocol that this configurer sets up.
   *
   * @return the protocol
   */
  public abstract @Nonnull AuthenticationProtocol getProtocol();

  /**
   * Assigns the protocol path, relative to the base URL. It must begin with a {@code /} and must not end with one. An
   * empty path places the endpoints directly under the base URL.
   *
   * @param path the protocol path
   * @return this configurer
   */
  public @Nonnull T path(final @Nonnull String path) {
    this.path = Objects.requireNonNull(path, "path must not be null");
    return this.self();
  }

  /**
   * Gets the protocol path.
   *
   * @return the protocol path
   */
  public @Nonnull String getPath() {
    return this.path;
  }

  /**
   * Assigns the protocol's single sign-on policy, which wins over the shared policy for requests made with this
   * protocol. A policy assigned to an authentication provider wins over both.
   *
   * @param ssoPolicy the policy, or {@code null} to use the shared policy
   * @return this configurer
   */
  public @Nonnull T ssoPolicy(final @Nullable SsoPolicy ssoPolicy) {
    this.ssoPolicy = ssoPolicy;
    return this.self();
  }

  /**
   * Gets the single sign-on policy that applies for this protocol: the protocol's own policy if assigned, and the shared
   * one otherwise.
   *
   * @return the single sign-on policy
   */
  public @Nonnull SsoPolicy getSsoPolicy() {
    return this.ssoPolicy != null ? this.ssoPolicy : this.getServer().getSsoPolicy();
  }

  /**
   * Assigns the protocol's clock skew, which wins over the shared value.
   *
   * @param clockSkew the clock skew, or {@code null} to use the shared value
   * @return this configurer
   */
  public @Nonnull T clockSkew(final @Nullable Duration clockSkew) {
    this.clockSkew = clockSkew;
    return this.self();
  }

  /**
   * Gets the clock skew that applies for this protocol.
   *
   * @return the clock skew
   */
  public @Nonnull Duration getClockSkew() {
    return this.clockSkew != null ? this.clockSkew : this.getServer().getClockSkew();
  }

  /**
   * Assigns whether the protocol supports user messages, which wins over the shared setting.
   *
   * @param supportsUserMessage whether user messages are supported, or {@code null} to use the shared setting
   * @return this configurer
   */
  public @Nonnull T supportsUserMessage(final @Nullable Boolean supportsUserMessage) {
    this.supportsUserMessage = supportsUserMessage;
    return this.self();
  }

  /**
   * Tells whether user messages are supported for this protocol.
   *
   * @return {@code true} if user messages are supported and {@code false} otherwise
   */
  public boolean isSupportsUserMessage() {
    return this.supportsUserMessage != null ? this.supportsUserMessage : this.getServer().isSupportsUserMessage();
  }

  /**
   * Assigns the protocol's subject identifier secret, which wins over the shared secret.
   *
   * @param secret the secret, or {@code null} to use the shared secret
   * @return this configurer
   */
  public @Nonnull T subjectIdentifierSecret(final @Nullable byte[] secret) {
    this.subjectIdentifierSecret = secret != null ? secret.clone() : null;
    return this.self();
  }

  /**
   * Gets the subject identifier secret that applies for this protocol.
   *
   * @return the secret, or {@code null} if no secret has been assigned
   */
  public @Nullable byte[] getSubjectIdentifierSecret() {
    return this.subjectIdentifierSecret != null
        ? this.subjectIdentifierSecret.clone()
        : this.getServer().getSubjectIdentifierSecret();
  }

  /**
   * Assigns the protocol's subject identifier hash algorithm, which wins over the shared algorithm.
   *
   * @param hashAlgorithm the JCE name of the hash algorithm, or {@code null} to use the shared algorithm
   * @return this configurer
   */
  public @Nonnull T subjectIdentifierHashAlgorithm(final @Nullable String hashAlgorithm) {
    this.subjectIdentifierHashAlgorithm = hashAlgorithm;
    return this.self();
  }

  /**
   * Gets the subject identifier hash algorithm that applies for this protocol.
   *
   * @return the JCE name of the hash algorithm
   */
  public @Nonnull String getSubjectIdentifierHashAlgorithm() {
    return this.subjectIdentifierHashAlgorithm != null
        ? this.subjectIdentifierHashAlgorithm
        : this.getServer().getSubjectIdentifierHashAlgorithm();
  }

  /**
   * Gets the path of an endpoint relative to the application, that is, the protocol path followed by the endpoint. This
   * is what a request matcher matches.
   *
   * @param endpoint the endpoint, relative to the protocol path
   * @return the path
   */
  public @Nonnull String getEndpointPath(final @Nonnull String endpoint) {
    return this.path + endpoint;
  }

  /**
   * Gets the URL of an endpoint: the base URL, the protocol path and the endpoint.
   *
   * @param endpoint the endpoint, relative to the protocol path
   * @return the URL
   */
  public @Nonnull String getEndpointUrl(final @Nonnull String endpoint) {
    return this.getServer().getBaseUrl() + this.getEndpointPath(endpoint);
  }

  /**
   * Gets the shared configurer that this configurer has been registered with.
   *
   * @return the shared configurer
   * @throws IllegalStateException if the configurer has not been registered
   */
  public @Nonnull AuthnServerConfigurer getServer() {
    if (this.server == null) {
      throw new IllegalStateException("The protocol configurer has not been registered with an AuthnServerConfigurer");
    }
    return this.server;
  }

  /**
   * Initializes the configurer: checks that its values are set and valid, and works out its endpoints.
   *
   * @param http the HTTP security object
   * @throws IllegalArgumentException if a required value is missing or a value is invalid
   */
  protected abstract void init(final @Nonnull HttpSecurity http);

  /**
   * Configures the {@link HttpSecurity} object, adding the protocol's filters.
   *
   * @param http the HTTP security object
   */
  protected abstract void configure(final @Nonnull HttpSecurity http);

  /**
   * Gets the request matcher for the protocol's endpoints. Invoked after {@link #init(HttpSecurity)}.
   *
   * @return a request matcher
   */
  protected abstract @Nonnull RequestMatcher getRequestMatcher();

  /**
   * Post processes an object created by the configurer, such as a filter.
   *
   * @param object the object
   * @param <O> the type of the object
   * @return the processed object
   */
  protected final @Nonnull <O> O postProcess(final @Nonnull O object) {
    return this.getServer().postProcessObject(object);
  }

  /**
   * Returns this object as its concrete type.
   *
   * @return this configurer
   */
  @SuppressWarnings("unchecked")
  protected final @Nonnull T self() {
    return (T) this;
  }

  /**
   * Registers the shared configurer. Invoked by {@link AuthnServerConfigurer#protocol(AbstractProtocolConfigurer)}.
   *
   * @param server the shared configurer
   */
  final void register(final @Nonnull AuthnServerConfigurer server) {
    this.server = server;
  }

  /**
   * Validates the protocol path and the values that override the shared ones, and then invokes
   * {@link #init(HttpSecurity)}.
   *
   * @param http the HTTP security object
   */
  final void doInit(final @Nonnull HttpSecurity http) {
    final String name = this.getProtocol().name();
    if (!this.path.isEmpty() && (!this.path.startsWith("/") || this.path.endsWith("/"))) {
      throw new IllegalArgumentException(
          "Invalid %s path '%s' - it must begin with / and must not end with /".formatted(name, this.path));
    }
    if (this.clockSkew != null) {
      AuthnServerConfigurer.assertClockSkew(this.clockSkew, name + " clock skew");
    }
    if (this.subjectIdentifierSecret != null && this.subjectIdentifierSecret.length == 0) {
      throw new IllegalArgumentException(name + " subject identifier secret must not be empty");
    }
    if (this.subjectIdentifierHashAlgorithm != null) {
      AuthnServerConfigurer.assertHashAlgorithm(this.subjectIdentifierHashAlgorithm,
          name + " subject identifier hash algorithm");
    }
    this.init(http);
  }

  /**
   * Gets the protocol's own single sign-on policy.
   *
   * @return the policy, or {@code null} if the shared policy applies
   */
  @Nullable
  SsoPolicy getProtocolSsoPolicy() {
    return this.ssoPolicy;
  }

}
