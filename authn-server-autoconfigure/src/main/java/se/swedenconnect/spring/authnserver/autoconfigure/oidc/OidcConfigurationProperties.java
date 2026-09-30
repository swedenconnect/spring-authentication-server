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

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;

import java.time.Duration;
import java.util.List;
import java.util.Map;

import org.springframework.boot.context.properties.ConfigurationProperties;

import se.swedenconnect.security.credential.config.properties.PkiCredentialConfigurationProperties;
import se.swedenconnect.spring.authnserver.autoconfigure.AuthnServerConfigurationProperties.SsoProperties;
import se.swedenconnect.spring.authnserver.autoconfigure.AuthnServerConfigurationProperties.SubjectIdentifierProperties;
import se.swedenconnect.spring.authnserver.oidc.keys.DecryptionKey;
import se.swedenconnect.spring.authnserver.oidc.keys.SigningKey;

/**
 * Configuration properties for the OpenID Provider.
 *
 * @author Martin Lindström
 */
@ConfigurationProperties(OidcConfigurationProperties.PREFIX)
public class OidcConfigurationProperties {

  /** The property prefix. */
  public static final String PREFIX = "authn-server.oidc";

  /**
   * Whether the OpenID Provider is enabled. Defaults to false.
   */
  private boolean enabled = false;

  /**
   * The OIDC path, relative to the base URL. The OIDC endpoints are placed under it. Defaults to /oidc.
   */
  private String path;

  /**
   * The issuer identifier of the OpenID Provider. It must be the base URL or begin with it. Defaults to the base URL.
   */
  private String issuer;

  /**
   * Single sign-on policy for OpenID Connect. Unassigned values are taken from authn-server.sso.
   */
  private final SsoProperties sso = new SsoProperties();

  /**
   * Clock skew for OpenID Connect. Overrides authn-server.clock-skew.
   */
  private Duration clockSkew;

  /**
   * Whether user messages are supported for OpenID Connect. Overrides authn-server.supports-user-message.
   */
  private Boolean supportsUserMessage;

  /**
   * Subject identifier settings for OpenID Connect. Overrides authn-server.subject-identifier.
   */
  private final SubjectIdentifierProperties subjectIdentifier = new SubjectIdentifierProperties();

  /**
   * The keys of the OpenID Provider.
   */
  private final KeyProperties keys = new KeyProperties();

  /**
   * The OIDC endpoints, relative to the OIDC path.
   */
  private final EndpointProperties endpoints = new EndpointProperties();

  /**
   * Whether UserInfo responses are signed. Defaults to true.
   */
  private Boolean signUserInfo;

  /**
   * The scopes that the OpenID Provider offers. When assigned, they replace the scopes derived from the
   * authentication providers.
   */
  private List<String> scopes;

  /**
   * Claims that are supported on top of those of the authentication providers.
   */
  private List<String> claims;

  /**
   * The languages that the user interface supports, as language tags.
   */
  private List<String> uiLocales;

  /**
   * The discovery document.
   */
  private final DiscoveryProperties discovery = new DiscoveryProperties();

  /**
   * Tells whether the OpenID Provider is enabled.
   *
   * @return whether the OpenID Provider is enabled
   */
  public boolean isEnabled() {
    return this.enabled;
  }

  /**
   * Assigns whether the OpenID Provider is enabled.
   *
   * @param enabled whether the OpenID Provider is enabled
   */
  public void setEnabled(final boolean enabled) {
    this.enabled = enabled;
  }

  /**
   * Gets the OIDC path.
   *
   * @return the OIDC path
   */
  public @Nullable String getPath() {
    return this.path;
  }

  /**
   * Assigns the OIDC path.
   *
   * @param path the OIDC path
   */
  public void setPath(final @Nullable String path) {
    this.path = path;
  }

  /**
   * Gets the issuer.
   *
   * @return the issuer
   */
  public @Nullable String getIssuer() {
    return this.issuer;
  }

  /**
   * Assigns the issuer.
   *
   * @param issuer the issuer
   */
  public void setIssuer(final @Nullable String issuer) {
    this.issuer = issuer;
  }

  /**
   * Gets the single sign-on properties.
   *
   * @return the single sign-on properties
   */
  public @Nonnull SsoProperties getSso() {
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
  public @Nonnull SubjectIdentifierProperties getSubjectIdentifier() {
    return this.subjectIdentifier;
  }

  /**
   * Gets the key properties.
   *
   * @return the key properties
   */
  public @Nonnull KeyProperties getKeys() {
    return this.keys;
  }

  /**
   * Gets the endpoint properties.
   *
   * @return the endpoint properties
   */
  public @Nonnull EndpointProperties getEndpoints() {
    return this.endpoints;
  }

  /**
   * Gets whether UserInfo responses are signed.
   *
   * @return whether UserInfo responses are signed
   */
  public @Nullable Boolean getSignUserInfo() {
    return this.signUserInfo;
  }

  /**
   * Assigns whether UserInfo responses are signed.
   *
   * @param signUserInfo whether UserInfo responses are signed
   */
  public void setSignUserInfo(final @Nullable Boolean signUserInfo) {
    this.signUserInfo = signUserInfo;
  }

  /**
   * Gets the configured scopes.
   *
   * @return the scopes
   */
  public @Nullable List<String> getScopes() {
    return this.scopes;
  }

  /**
   * Assigns the configured scopes.
   *
   * @param scopes the scopes
   */
  public void setScopes(final @Nullable List<String> scopes) {
    this.scopes = scopes;
  }

  /**
   * Gets the configured claims.
   *
   * @return the claims
   */
  public @Nullable List<String> getClaims() {
    return this.claims;
  }

  /**
   * Assigns the configured claims.
   *
   * @param claims the claims
   */
  public void setClaims(final @Nullable List<String> claims) {
    this.claims = claims;
  }

  /**
   * Gets the UI locales.
   *
   * @return the UI locales
   */
  public @Nullable List<String> getUiLocales() {
    return this.uiLocales;
  }

  /**
   * Assigns the UI locales.
   *
   * @param uiLocales the UI locales
   */
  public void setUiLocales(final @Nullable List<String> uiLocales) {
    this.uiLocales = uiLocales;
  }

  /**
   * Gets the discovery properties.
   *
   * @return the discovery properties
   */
  public @Nonnull DiscoveryProperties getDiscovery() {
    return this.discovery;
  }

  /**
   * The keys of the OpenID Provider.
   */
  public static class KeyProperties {

    /**
     * The signing keys. At least one active key is required, and exactly one active key is the default key. With one
     * active key, it is the default key.
     */
    private List<SigningKeyProperties> signing;

    /**
     * The decryption keys, used for encrypted request objects.
     */
    private List<DecryptionKeyProperties> decryption;

    /**
     * Gets the signing keys.
     *
     * @return the signing keys
     */
    public @Nullable List<SigningKeyProperties> getSigning() {
      return this.signing;
    }

    /**
     * Assigns the signing keys.
     *
     * @param signing the signing keys
     */
    public void setSigning(final @Nullable List<SigningKeyProperties> signing) {
      this.signing = signing;
    }

    /**
     * Gets the decryption keys.
     *
     * @return the decryption keys
     */
    public @Nullable List<DecryptionKeyProperties> getDecryption() {
      return this.decryption;
    }

    /**
     * Assigns the decryption keys.
     *
     * @param decryption the decryption keys
     */
    public void setDecryption(final @Nullable List<DecryptionKeyProperties> decryption) {
      this.decryption = decryption;
    }
  }

  /**
   * A signing key.
   */
  public static class SigningKeyProperties {

    /**
     * The credential holding the key.
     */
    private PkiCredentialConfigurationProperties credential;

    /**
     * The state of the key: active, it is published and used, or future, it is published but not used. Defaults to
     * active.
     */
    private SigningKey.State state = SigningKey.State.ACTIVE;

    /**
     * Whether this is the default key. Only for an active key.
     */
    private boolean defaultKey = false;

    /**
     * Gets the credential.
     *
     * @return the credential
     */
    public @Nullable PkiCredentialConfigurationProperties getCredential() {
      return this.credential;
    }

    /**
     * Assigns the credential.
     *
     * @param credential the credential
     */
    public void setCredential(final @Nullable PkiCredentialConfigurationProperties credential) {
      this.credential = credential;
    }

    /**
     * Gets the state.
     *
     * @return the state
     */
    public @Nonnull SigningKey.State getState() {
      return this.state;
    }

    /**
     * Assigns the state.
     *
     * @param state the state
     */
    public void setState(final @Nonnull SigningKey.State state) {
      this.state = state;
    }

    /**
     * Gets whether this is the default key.
     *
     * @return whether this is the default key
     */
    public boolean isDefaultKey() {
      return this.defaultKey;
    }

    /**
     * Assigns whether this is the default key.
     *
     * @param defaultKey whether this is the default key
     */
    public void setDefaultKey(final boolean defaultKey) {
      this.defaultKey = defaultKey;
    }
  }

  /**
   * A decryption key.
   */
  public static class DecryptionKeyProperties {

    /**
     * The credential holding the key.
     */
    private PkiCredentialConfigurationProperties credential;

    /**
     * The state of the key: active, it is published and used, or previous, it is not published but still used for
     * decryption. Defaults to active.
     */
    private DecryptionKey.State state = DecryptionKey.State.ACTIVE;

    /**
     * Gets the credential.
     *
     * @return the credential
     */
    public @Nullable PkiCredentialConfigurationProperties getCredential() {
      return this.credential;
    }

    /**
     * Assigns the credential.
     *
     * @param credential the credential
     */
    public void setCredential(final @Nullable PkiCredentialConfigurationProperties credential) {
      this.credential = credential;
    }

    /**
     * Gets the state.
     *
     * @return the state
     */
    public @Nonnull DecryptionKey.State getState() {
      return this.state;
    }

    /**
     * Assigns the state.
     *
     * @param state the state
     */
    public void setState(final @Nonnull DecryptionKey.State state) {
      this.state = state;
    }
  }

  /**
   * The OIDC endpoints.
   */
  public static class EndpointProperties {

    /**
     * Where the JWKS is published. Defaults to /jwks.
     */
    private String jwks;

    /**
     * Gets the JWKS endpoint.
     *
     * @return the JWKS endpoint
     */
    public @Nullable String getJwks() {
      return this.jwks;
    }

    /**
     * Assigns the JWKS endpoint.
     *
     * @param jwks the JWKS endpoint
     */
    public void setJwks(final @Nullable String jwks) {
      this.jwks = jwks;
    }
  }

  /**
   * The discovery document.
   */
  public static class DiscoveryProperties {

    /**
     * Parameters that are added to the discovery document, for example service_documentation or op_policy_uri. A
     * parameter that the OpenID Provider sets itself cannot be given here.
     */
    private Map<String, Object> additionalParameters;

    /**
     * Gets the additional parameters.
     *
     * @return the additional parameters
     */
    public @Nullable Map<String, Object> getAdditionalParameters() {
      return this.additionalParameters;
    }

    /**
     * Assigns the additional parameters.
     *
     * @param additionalParameters the additional parameters
     */
    public void setAdditionalParameters(final @Nullable Map<String, Object> additionalParameters) {
      this.additionalParameters = additionalParameters;
    }
  }

}
