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
package se.swedenconnect.spring.authnserver.autoconfigure;

import java.nio.charset.StandardCharsets;
import java.time.Duration;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.boot.context.properties.ConfigurationProperties;

import se.swedenconnect.spring.authnserver.config.AuthnServerConfigurer;
import se.swedenconnect.spring.authnserver.entity.EntityInformation;
import se.swedenconnect.spring.authnserver.sso.SsoPolicy;

/**
 * Configuration properties for the values that are common to all protocols. Some of them may be overridden per
 * protocol.
 *
 * @author Martin Lindström
 */
@ConfigurationProperties(AuthnServerConfigurationProperties.PREFIX)
public class AuthnServerConfigurationProperties {

  /** The property prefix. */
  public static final String PREFIX = "authn-server";

  /**
   * The base URL of the server: protocol, host and context path, for example https://idp.example.com/auth. Must not
   * end with a '/'. Required.
   */
  private String baseUrl;

  /**
   * The single sign-on policy of the server.
   */
  private final SsoProperties sso = new SsoProperties();

  /**
   * The time that clocks of other parties may differ from the server clock. Defaults to 30 seconds.
   */
  private Duration clockSkew;

  /**
   * Whether the server supports displaying a user message from the requester. Defaults to false.
   */
  private Boolean supportsUserMessage;

  /**
   * Settings for computing subject identifiers (SAML NameID and OIDC sub).
   */
  private final SubjectIdentifierProperties subjectIdentifier = new SubjectIdentifierProperties();

  /**
   * The maximum age of an authentication in progress, that is, how long the server waits for the user to come back
   * from an authentication module. Defaults to 30 minutes.
   */
  private Duration authnFlowMaxAge;

  /**
   * The descriptive information about the server and its organization that every protocol publishes: the SAML
   * metadata and the OpenID Federation entity configuration. A protocol may override any part of it.
   */
  private final EntityInformationProperties entityInformation = new EntityInformationProperties();

  /**
   * Gets the base URL.
   *
   * @return the base URL
   */
  public @Nullable String getBaseUrl() {
    return this.baseUrl;
  }

  /**
   * Assigns the base URL.
   *
   * @param baseUrl the base URL
   */
  public void setBaseUrl(final @Nullable String baseUrl) {
    this.baseUrl = baseUrl;
  }

  /**
   * Gets the single sign-on properties.
   *
   * @return the single sign-on properties
   */
  public @NonNull SsoProperties getSso() {
    return this.sso;
  }

  /**
   * Gets the clock skew.
   *
   * @return the clock skew
   */
  public @Nullable Duration getClockSkew() {
    return this.clockSkew;
  }

  /**
   * Assigns the clock skew.
   *
   * @param clockSkew the clock skew
   */
  public void setClockSkew(final @Nullable Duration clockSkew) {
    this.clockSkew = clockSkew;
  }

  /**
   * Gets whether user messages are supported.
   *
   * @return whether user messages are supported
   */
  public @Nullable Boolean getSupportsUserMessage() {
    return this.supportsUserMessage;
  }

  /**
   * Assigns whether user messages are supported.
   *
   * @param supportsUserMessage whether user messages are supported
   */
  public void setSupportsUserMessage(final @Nullable Boolean supportsUserMessage) {
    this.supportsUserMessage = supportsUserMessage;
  }

  /**
   * Gets the subject identifier properties.
   *
   * @return the subject identifier properties
   */
  public @NonNull SubjectIdentifierProperties getSubjectIdentifier() {
    return this.subjectIdentifier;
  }

  /**
   * Gets the maximum age of an authentication in progress.
   *
   * @return the maximum age
   */
  public @Nullable Duration getAuthnFlowMaxAge() {
    return this.authnFlowMaxAge;
  }

  /**
   * Assigns the maximum age of an authentication in progress.
   *
   * @param authnFlowMaxAge the maximum age
   */
  public void setAuthnFlowMaxAge(final @Nullable Duration authnFlowMaxAge) {
    this.authnFlowMaxAge = authnFlowMaxAge;
  }

  /**
   * Gets the shared entity information.
   *
   * @return the entity information properties
   */
  public @NonNull EntityInformationProperties getEntityInformation() {
    return this.entityInformation;
  }

  /**
   * Applies the property values to a shared configurer. Values that have not been assigned are left at the configurer's
   * defaults.
   *
   * @param configurer the configurer
   */
  public void applyTo(final @NonNull AuthnServerConfigurer configurer) {
    if (this.baseUrl != null) {
      configurer.baseUrl(this.baseUrl);
    }
    if (this.sso.isAssigned()) {
      configurer.ssoPolicy(this.sso.toPolicy(configurer.getSsoPolicy(), PREFIX + ".sso"));
    }
    if (this.clockSkew != null) {
      configurer.clockSkew(this.clockSkew);
    }
    if (this.supportsUserMessage != null) {
      configurer.supportsUserMessage(this.supportsUserMessage);
    }
    if (this.subjectIdentifier.getSecret() != null) {
      configurer.subjectIdentifierSecret(this.subjectIdentifier.getSecretBytes());
    }
    if (this.subjectIdentifier.getHashAlgorithm() != null) {
      configurer.subjectIdentifierHashAlgorithm(this.subjectIdentifier.getHashAlgorithm());
    }
    if (this.authnFlowMaxAge != null) {
      configurer.authnFlowMaxAge(this.authnFlowMaxAge);
    }
    final EntityInformation information = this.entityInformation.toEntityInformation();
    if (!information.isEmpty()) {
      configurer.entityInformation(information);
    }
  }

  /**
   * Single sign-on properties. A value that is not assigned is taken from the level above: the protocol properties take
   * their unassigned values from the shared properties, and the shared properties from the defaults.
   */
  public static class SsoProperties {

    /**
     * Whether single sign-on is allowed at all. Defaults to true.
     */
    private Boolean enabled;

    /**
     * How old a previous authentication may be for it to be reused. Defaults to 60 minutes. Must be positive. To turn
     * single sign-on off, use the enabled setting.
     */
    private Duration timeLimit;

    /**
     * Whether a previous authentication may only be reused for the requester it was made for. Defaults to true.
     */
    private Boolean sameRequesterRequired;

    /**
     * Gets whether single sign-on is enabled.
     *
     * @return whether single sign-on is enabled
     */
    public @Nullable Boolean getEnabled() {
      return this.enabled;
    }

    /**
     * Assigns whether single sign-on is enabled.
     *
     * @param enabled whether single sign-on is enabled
     */
    public void setEnabled(final @Nullable Boolean enabled) {
      this.enabled = enabled;
    }

    /**
     * Gets the time limit.
     *
     * @return the time limit
     */
    public @Nullable Duration getTimeLimit() {
      return this.timeLimit;
    }

    /**
     * Assigns the time limit.
     *
     * @param timeLimit the time limit
     */
    public void setTimeLimit(final @Nullable Duration timeLimit) {
      this.timeLimit = timeLimit;
    }

    /**
     * Gets whether the same requester is required.
     *
     * @return whether the same requester is required
     */
    public @Nullable Boolean getSameRequesterRequired() {
      return this.sameRequesterRequired;
    }

    /**
     * Assigns whether the same requester is required.
     *
     * @param sameRequesterRequired whether the same requester is required
     */
    public void setSameRequesterRequired(final @Nullable Boolean sameRequesterRequired) {
      this.sameRequesterRequired = sameRequesterRequired;
    }

    /**
     * Tells whether any value has been assigned.
     *
     * @return {@code true} if a value has been assigned and {@code false} otherwise
     */
    public boolean isAssigned() {
      return this.enabled != null || this.timeLimit != null || this.sameRequesterRequired != null;
    }

    /**
     * Creates a policy from the assigned values, taking the unassigned ones from a base policy.
     *
     * @param base the base policy
     * @param prefix the property prefix of these properties, used in error messages
     * @return a new policy
     * @throws IllegalArgumentException if the time limit is not positive
     */
    public @NonNull SsoPolicy toPolicy(final @NonNull SsoPolicy base, final @NonNull String prefix) {
      if (this.timeLimit != null && (this.timeLimit.isZero() || this.timeLimit.isNegative())) {
        throw new IllegalArgumentException(
            "%s.time-limit must be positive - to turn single sign-on off, set %s.enabled to false"
                .formatted(prefix, prefix));
      }
      final SsoPolicy policy = new SsoPolicy();
      policy.setEnabled(this.enabled != null ? this.enabled : base.isEnabled());
      policy.setTimeLimit(this.timeLimit != null ? this.timeLimit : base.getTimeLimit());
      policy.setSameRequesterRequired(
          this.sameRequesterRequired != null ? this.sameRequesterRequired : base.isSameRequesterRequired());
      return policy;
    }
  }

  /**
   * Properties for computing subject identifiers.
   */
  public static class SubjectIdentifierProperties {

    /**
     * The secret that takes part in the computation of subject identifiers. Assigning a secret is strongly
     * recommended. The UTF-8 bytes of the string are used.
     */
    private String secret;

    /**
     * The JCE name of the hash algorithm used for subject identifiers. Defaults to SHA-256.
     */
    private String hashAlgorithm;

    /**
     * Gets the secret.
     *
     * @return the secret
     */
    public @Nullable String getSecret() {
      return this.secret;
    }

    /**
     * Assigns the secret.
     *
     * @param secret the secret
     */
    public void setSecret(final @Nullable String secret) {
      this.secret = secret;
    }

    /**
     * Gets the secret as bytes.
     *
     * @return the UTF-8 bytes of the secret, or {@code null}
     */
    public byte @Nullable [] getSecretBytes() {
      return this.secret != null ? this.secret.getBytes(StandardCharsets.UTF_8) : null;
    }

    /**
     * Gets the hash algorithm.
     *
     * @return the hash algorithm
     */
    public @Nullable String getHashAlgorithm() {
      return this.hashAlgorithm;
    }

    /**
     * Assigns the hash algorithm.
     *
     * @param hashAlgorithm the hash algorithm
     */
    public void setHashAlgorithm(final @Nullable String hashAlgorithm) {
      this.hashAlgorithm = hashAlgorithm;
    }
  }

}
