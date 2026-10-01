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

import java.io.File;
import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Map;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.io.Resource;

import se.swedenconnect.security.credential.config.properties.PkiCredentialConfigurationProperties;
import se.swedenconnect.spring.authnserver.autoconfigure.AuthnServerConfigurationProperties.SsoProperties;
import se.swedenconnect.spring.authnserver.autoconfigure.AuthnServerConfigurationProperties.SubjectIdentifierProperties;
import se.swedenconnect.spring.authnserver.autoconfigure.EntityInformationProperties;
import se.swedenconnect.spring.authnserver.oidc.federation.OidcEntityMetadata;
import se.swedenconnect.spring.authnserver.oidc.keys.DecryptionKey;
import se.swedenconnect.spring.authnserver.oidc.keys.FederationKey;
import se.swedenconnect.spring.authnserver.oidc.keys.SigningKey;
import se.swedenconnect.spring.authnserver.registry.acceptance.ConfigurableRequesterAcceptance;

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
   * The processing of authentication requests.
   */
  private final AuthorizationRequestProperties authorizationRequest = new AuthorizationRequestProperties();

  /**
   * The lifetimes and use of authorization codes, access tokens and ID tokens.
   */
  private final TokenProperties tokens = new TokenProperties();

  /**
   * The client authentication methods that are enabled at the token endpoint: private_key_jwt, client_secret_basic,
   * client_secret_post and client_secret_jwt. Defaults to private_key_jwt.
   */
  private List<String> clientAuthenticationMethods;

  /**
   * The rules for which clients are accepted. Without rules, every client that the client registry knows is accepted.
   */
  private final RequesterAcceptanceProperties requesterAcceptance = new RequesterAcceptanceProperties();

  /**
   * The descriptive information for OpenID Connect. The values assigned override those of
   * authn-server.entity-information, and the OIDC metadata parameters may be given directly.
   */
  private final OidcEntityInformationProperties entityInformation = new OidcEntityInformationProperties();

  /**
   * The OpenID Provider as a member of an OpenID Federation.
   */
  private final FederationProperties federation = new FederationProperties();

  /**
   * Where each of the OpenID Provider's stores is kept, overriding authn-server.storage.type for that store.
   */
  private final StorageProperties storage = new StorageProperties();

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
   * Gets the key properties.
   *
   * @return the key properties
   */
  public @NonNull KeyProperties getKeys() {
    return this.keys;
  }

  /**
   * Gets the endpoint properties.
   *
   * @return the endpoint properties
   */
  public @NonNull EndpointProperties getEndpoints() {
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
  public @NonNull DiscoveryProperties getDiscovery() {
    return this.discovery;
  }

  /**
   * Gets the properties for the processing of authentication requests.
   *
   * @return the authorization request properties
   */
  public @NonNull AuthorizationRequestProperties getAuthorizationRequest() {
    return this.authorizationRequest;
  }

  /**
   * Gets the token properties.
   *
   * @return the token properties
   */
  public @NonNull TokenProperties getTokens() {
    return this.tokens;
  }

  /**
   * Gets the enabled client authentication methods.
   *
   * @return the methods, or {@code null} for the default
   */
  public @Nullable List<String> getClientAuthenticationMethods() {
    return this.clientAuthenticationMethods;
  }

  /**
   * Assigns the enabled client authentication methods.
   *
   * @param clientAuthenticationMethods the methods
   */
  public void setClientAuthenticationMethods(final @Nullable List<String> clientAuthenticationMethods) {
    this.clientAuthenticationMethods = clientAuthenticationMethods;
  }

  /**
   * Gets the requester acceptance properties.
   *
   * @return the requester acceptance properties
   */
  public @NonNull RequesterAcceptanceProperties getRequesterAcceptance() {
    return this.requesterAcceptance;
  }

  /**
   * Gets the entity information properties.
   *
   * @return the entity information properties
   */
  public @NonNull OidcEntityInformationProperties getEntityInformation() {
    return this.entityInformation;
  }

  /**
   * Gets the federation properties.
   *
   * @return the federation properties
   */
  public @NonNull FederationProperties getFederation() {
    return this.federation;
  }

  /**
   * Gets the storage properties.
   *
   * @return the storage properties
   */
  public @NonNull StorageProperties getStorage() {
    return this.storage;
  }

  /**
   * The descriptive information for OpenID Connect: overrides of the shared information, and values of the OIDC
   * metadata parameters that replace what is otherwise taken from the information.
   */
  public static class OidcEntityInformationProperties extends EntityInformationProperties {

    /**
     * The display_name parameter, keyed by language tag. Defaults to the UI display names.
     */
    private Map<String, String> displayName;

    /**
     * The description parameter, keyed by language tag. Defaults to the UI descriptions.
     */
    private Map<String, String> description;

    /**
     * The organization_name parameter, keyed by language tag. Defaults to the organization names.
     */
    private Map<String, String> organizationName;

    /**
     * The organization_uri parameter. Defaults to the first organization URL.
     */
    private String organizationUri;

    /**
     * The organization_identifier parameter. Defaults to urn:glue:iso6523:0007 followed by the organization number, when
     * it is ten digits.
     */
    private String organizationIdentifier;

    /**
     * The logo_uri parameter. Defaults to the first logo without a language, or else the first logo.
     */
    private String logoUri;

    /**
     * The contacts parameter. Defaults to the e-mail addresses of the technical and support contact persons.
     */
    private List<String> contacts;

    /**
     * Gets the display names.
     *
     * @return the display names
     */
    public @Nullable Map<String, String> getDisplayName() {
      return this.displayName;
    }

    /**
     * Assigns the display names.
     *
     * @param displayName the display names
     */
    public void setDisplayName(final @Nullable Map<String, String> displayName) {
      this.displayName = displayName;
    }

    /**
     * Gets the descriptions.
     *
     * @return the descriptions
     */
    public @Nullable Map<String, String> getDescription() {
      return this.description;
    }

    /**
     * Assigns the descriptions.
     *
     * @param description the descriptions
     */
    public void setDescription(final @Nullable Map<String, String> description) {
      this.description = description;
    }

    /**
     * Gets the organization names.
     *
     * @return the organization names
     */
    public @Nullable Map<String, String> getOrganizationName() {
      return this.organizationName;
    }

    /**
     * Assigns the organization names.
     *
     * @param organizationName the organization names
     */
    public void setOrganizationName(final @Nullable Map<String, String> organizationName) {
      this.organizationName = organizationName;
    }

    /**
     * Gets the organization URI.
     *
     * @return the organization URI
     */
    public @Nullable String getOrganizationUri() {
      return this.organizationUri;
    }

    /**
     * Assigns the organization URI.
     *
     * @param organizationUri the organization URI
     */
    public void setOrganizationUri(final @Nullable String organizationUri) {
      this.organizationUri = organizationUri;
    }

    /**
     * Gets the organization identifier.
     *
     * @return the organization identifier
     */
    public @Nullable String getOrganizationIdentifier() {
      return this.organizationIdentifier;
    }

    /**
     * Assigns the organization identifier.
     *
     * @param organizationIdentifier the organization identifier
     */
    public void setOrganizationIdentifier(final @Nullable String organizationIdentifier) {
      this.organizationIdentifier = organizationIdentifier;
    }

    /**
     * Gets the logo URI.
     *
     * @return the logo URI
     */
    public @Nullable String getLogoUri() {
      return this.logoUri;
    }

    /**
     * Assigns the logo URI.
     *
     * @param logoUri the logo URI
     */
    public void setLogoUri(final @Nullable String logoUri) {
      this.logoUri = logoUri;
    }

    /**
     * Gets the contacts.
     *
     * @return the contacts
     */
    public @Nullable List<String> getContacts() {
      return this.contacts;
    }

    /**
     * Assigns the contacts.
     *
     * @param contacts the contacts
     */
    public void setContacts(final @Nullable List<String> contacts) {
      this.contacts = contacts;
    }

    /**
     * Creates the OIDC metadata parameter values of the properties.
     *
     * @return an {@link OidcEntityMetadata}
     */
    public @NonNull OidcEntityMetadata toEntityMetadata() {
      return new OidcEntityMetadata(this.displayName, this.description, this.organizationName, this.organizationUri,
          this.organizationIdentifier, this.logoUri, this.contacts);
    }
  }

  /**
   * The OpenID Provider as a member of an OpenID Federation.
   */
  public static class FederationProperties {

    /**
     * Whether the OpenID Provider is a member of an OpenID Federation and publishes an entity configuration. Defaults
     * to false.
     */
    private boolean enabled = false;

    /**
     * The entity identifiers of the immediate superiors of the OpenID Provider. At least one is required when
     * federation is enabled.
     */
    private List<String> authorityHints;

    /**
     * The federation keys, that the entity configuration is signed with. At least one active key is required when
     * federation is enabled.
     */
    private List<FederationKeyProperties> keys;

    /**
     * The lifetime of the entity configuration. Defaults to 1 day.
     */
    private Duration entityConfigurationLifetime;

    /**
     * Parameters applied to the entity configuration, for example trust_anchor_hints. A metadata entry is merged into
     * the metadata per entity type and parameter.
     */
    private Map<String, Object> additionalParameters;

    /**
     * The trust marks of the OpenID Provider, one per trust mark type.
     */
    private List<TrustMarkProperties> trustMarks;

    /**
     * A directory where fetched trust marks are stored, so that they are available after a restart. Overrides the
     * directory oidc/trust-marks of authn-server.cache-directory. Without either, nothing is stored. Not used when the
     * trust marks are kept in Redis.
     */
    private File trustMarkCacheDirectory;

    /**
     * The interval between two attempts to fetch a trust mark after a failure. Defaults to 5 minutes.
     */
    private Duration trustMarkRetryInterval;

    /**
     * Tells whether federation is enabled.
     *
     * @return whether federation is enabled
     */
    public boolean isEnabled() {
      return this.enabled;
    }

    /**
     * Assigns whether federation is enabled.
     *
     * @param enabled whether federation is enabled
     */
    public void setEnabled(final boolean enabled) {
      this.enabled = enabled;
    }

    /**
     * Gets the authority hints.
     *
     * @return the authority hints
     */
    public @Nullable List<String> getAuthorityHints() {
      return this.authorityHints;
    }

    /**
     * Assigns the authority hints.
     *
     * @param authorityHints the authority hints
     */
    public void setAuthorityHints(final @Nullable List<String> authorityHints) {
      this.authorityHints = authorityHints;
    }

    /**
     * Gets the federation keys.
     *
     * @return the federation keys
     */
    public @Nullable List<FederationKeyProperties> getKeys() {
      return this.keys;
    }

    /**
     * Assigns the federation keys.
     *
     * @param keys the federation keys
     */
    public void setKeys(final @Nullable List<FederationKeyProperties> keys) {
      this.keys = keys;
    }

    /**
     * Gets the lifetime of the entity configuration.
     *
     * @return the lifetime, or {@code null} for the default
     */
    public @Nullable Duration getEntityConfigurationLifetime() {
      return this.entityConfigurationLifetime;
    }

    /**
     * Assigns the lifetime of the entity configuration.
     *
     * @param entityConfigurationLifetime the lifetime
     */
    public void setEntityConfigurationLifetime(final @Nullable Duration entityConfigurationLifetime) {
      this.entityConfigurationLifetime = entityConfigurationLifetime;
    }

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

    /**
     * Gets the trust marks.
     *
     * @return the trust marks
     */
    public @Nullable List<TrustMarkProperties> getTrustMarks() {
      return this.trustMarks;
    }

    /**
     * Assigns the trust marks.
     *
     * @param trustMarks the trust marks
     */
    public void setTrustMarks(final @Nullable List<TrustMarkProperties> trustMarks) {
      this.trustMarks = trustMarks;
    }

    /**
     * Gets the trust mark cache directory.
     *
     * @return the directory, or {@code null}
     */
    public @Nullable File getTrustMarkCacheDirectory() {
      return this.trustMarkCacheDirectory;
    }

    /**
     * Assigns the trust mark cache directory.
     *
     * @param trustMarkCacheDirectory the directory
     */
    public void setTrustMarkCacheDirectory(final @Nullable File trustMarkCacheDirectory) {
      this.trustMarkCacheDirectory = trustMarkCacheDirectory;
    }

    /**
     * Gets the trust mark retry interval.
     *
     * @return the interval, or {@code null} for the default
     */
    public @Nullable Duration getTrustMarkRetryInterval() {
      return this.trustMarkRetryInterval;
    }

    /**
     * Assigns the trust mark retry interval.
     *
     * @param trustMarkRetryInterval the interval
     */
    public void setTrustMarkRetryInterval(final @Nullable Duration trustMarkRetryInterval) {
      this.trustMarkRetryInterval = trustMarkRetryInterval;
    }
  }

  /**
   * A federation key.
   */
  public static class FederationKeyProperties {

    /**
     * The credential holding the key.
     */
    private PkiCredentialConfigurationProperties credential;

    /**
     * The state of the key: active, it is published and used, or future, it is published but not used. Defaults to
     * active.
     */
    private FederationKey.State state = FederationKey.State.ACTIVE;

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
    public FederationKey.@NonNull State getState() {
      return this.state;
    }

    /**
     * Assigns the state.
     *
     * @param state the state
     */
    public void setState(final FederationKey.@NonNull State state) {
      this.state = state;
    }
  }

  /**
   * A trust mark of the OpenID Provider and where it is fetched.
   */
  public static class TrustMarkProperties {

    /**
     * The trust mark type.
     */
    private String type;

    /**
     * The entity identifier of the trust mark issuer.
     */
    private String issuer;

    /**
     * The trust mark endpoint of the issuer.
     */
    private URI endpoint;

    /**
     * A JWK Set document holding the federation keys of the issuer, that the trust mark is verified with.
     */
    private Resource jwks;

    /**
     * Gets the trust mark type.
     *
     * @return the trust mark type
     */
    public @Nullable String getType() {
      return this.type;
    }

    /**
     * Assigns the trust mark type.
     *
     * @param type the trust mark type
     */
    public void setType(final @Nullable String type) {
      this.type = type;
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
     * Gets the trust mark endpoint.
     *
     * @return the endpoint
     */
    public @Nullable URI getEndpoint() {
      return this.endpoint;
    }

    /**
     * Assigns the trust mark endpoint.
     *
     * @param endpoint the endpoint
     */
    public void setEndpoint(final @Nullable URI endpoint) {
      this.endpoint = endpoint;
    }

    /**
     * Gets the JWK Set of the issuer.
     *
     * @return the JWK Set resource
     */
    public @Nullable Resource getJwks() {
      return this.jwks;
    }

    /**
     * Assigns the JWK Set of the issuer.
     *
     * @param jwks the JWK Set resource
     */
    public void setJwks(final @Nullable Resource jwks) {
      this.jwks = jwks;
    }
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
    public SigningKey.@NonNull State getState() {
      return this.state;
    }

    /**
     * Assigns the state.
     *
     * @param state the state
     */
    public void setState(final SigningKey.@NonNull State state) {
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
    public DecryptionKey.@NonNull State getState() {
      return this.state;
    }

    /**
     * Assigns the state.
     *
     * @param state the state
     */
    public void setState(final DecryptionKey.@NonNull State state) {
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
     * Where authentication requests are received. Defaults to /authorize.
     */
    private String authorization;

    /**
     * Where token requests are received. Defaults to /token.
     */
    private String token;

    /**
     * Where UserInfo requests are received. Defaults to /userinfo.
     */
    private String userinfo;

    /**
     * Gets the UserInfo endpoint.
     *
     * @return the UserInfo endpoint
     */
    public @Nullable String getUserinfo() {
      return this.userinfo;
    }

    /**
     * Assigns the UserInfo endpoint.
     *
     * @param userinfo the UserInfo endpoint
     */
    public void setUserinfo(final @Nullable String userinfo) {
      this.userinfo = userinfo;
    }

    /**
     * Gets the token endpoint.
     *
     * @return the token endpoint
     */
    public @Nullable String getToken() {
      return this.token;
    }

    /**
     * Assigns the token endpoint.
     *
     * @param token the token endpoint
     */
    public void setToken(final @Nullable String token) {
      this.token = token;
    }

    /**
     * Gets the authorization endpoint.
     *
     * @return the authorization endpoint
     */
    public @Nullable String getAuthorization() {
      return this.authorization;
    }

    /**
     * Assigns the authorization endpoint.
     *
     * @param authorization the authorization endpoint
     */
    public void setAuthorization(final @Nullable String authorization) {
      this.authorization = authorization;
    }

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

  /**
   * The processing of authentication requests.
   */
  public static class AuthorizationRequestProperties {

    /**
     * Whether PKCE is required. Defaults to false, which means that PKCE is optional. The plain method is never
     * accepted.
     */
    private Boolean requirePkce;

    /**
     * Whether request objects must be signed. Defaults to false, which means that an unsigned request object is
     * accepted unless the client has registered request_object_signing_alg.
     */
    private Boolean requireSignedRequestObject;

    /**
     * Whether authentication requests must carry state. Defaults to true.
     */
    private Boolean requireState;

    /**
     * Gets whether PKCE is required.
     *
     * @return whether PKCE is required, or {@code null} for the default
     */
    public @Nullable Boolean getRequirePkce() {
      return this.requirePkce;
    }

    /**
     * Assigns whether PKCE is required.
     *
     * @param requirePkce whether PKCE is required
     */
    public void setRequirePkce(final @Nullable Boolean requirePkce) {
      this.requirePkce = requirePkce;
    }

    /**
     * Gets whether request objects must be signed.
     *
     * @return whether request objects must be signed, or {@code null} for the default
     */
    public @Nullable Boolean getRequireSignedRequestObject() {
      return this.requireSignedRequestObject;
    }

    /**
     * Assigns whether request objects must be signed.
     *
     * @param requireSignedRequestObject whether request objects must be signed
     */
    public void setRequireSignedRequestObject(final @Nullable Boolean requireSignedRequestObject) {
      this.requireSignedRequestObject = requireSignedRequestObject;
    }

    /**
     * Gets whether authentication requests must carry state.
     *
     * @return whether state is required, or {@code null} for the default
     */
    public @Nullable Boolean getRequireState() {
      return this.requireState;
    }

    /**
     * Assigns whether authentication requests must carry state.
     *
     * @param requireState whether state is required
     */
    public void setRequireState(final @Nullable Boolean requireState) {
      this.requireState = requireState;
    }
  }

  /**
   * Configuration properties for requester acceptance.
   */
  public static class RequesterAcceptanceProperties {

    /**
     * How the rules are combined: ALL (every rule must accept) or ANY (one accepting rule is enough). Defaults to
     * ALL.
     */
    private ConfigurableRequesterAcceptance.Mode mode;

    /**
     * The client_ids of the accepted clients.
     */
    private List<String> whitelist;

    /**
     * Groups of trust mark types. Every group must be satisfied, and a group is satisfied by any one of its trust mark
     * types. A trust mark that the client lacks is requested through the client registry before the client is
     * rejected.
     */
    private List<List<String>> requiredMarks;

    /**
     * Gets the combination mode.
     *
     * @return the combination mode
     */
    public ConfigurableRequesterAcceptance.@Nullable Mode getMode() {
      return this.mode;
    }

    /**
     * Assigns the combination mode.
     *
     * @param mode the combination mode
     */
    public void setMode(final ConfigurableRequesterAcceptance.@Nullable Mode mode) {
      this.mode = mode;
    }

    /**
     * Gets the whitelist.
     *
     * @return the whitelist
     */
    public @Nullable List<String> getWhitelist() {
      return this.whitelist;
    }

    /**
     * Assigns the whitelist.
     *
     * @param whitelist the whitelist
     */
    public void setWhitelist(final @Nullable List<String> whitelist) {
      this.whitelist = whitelist;
    }

    /**
     * Gets the required mark groups.
     *
     * @return the required mark groups
     */
    public @Nullable List<List<String>> getRequiredMarks() {
      return this.requiredMarks;
    }

    /**
     * Assigns the required mark groups.
     *
     * @param requiredMarks the required mark groups
     */
    public void setRequiredMarks(final @Nullable List<List<String>> requiredMarks) {
      this.requiredMarks = requiredMarks;
    }
  }

  /**
   * The lifetimes and use of authorization codes, access tokens and ID tokens.
   */
  public static class TokenProperties {

    /**
     * The authorization code lifetime. Defaults to 1 minute. A lifetime above 10 minutes is logged as a warning.
     */
    private Duration authorizationCodeLifetime;

    /**
     * The access token lifetime. Defaults to 5 minutes.
     */
    private Duration accessTokenLifetime;

    /**
     * Whether an access token may only be used once, at the UserInfo endpoint. Defaults to true.
     */
    private Boolean accessTokenSingleUse;

    /**
     * The ID token lifetime. Defaults to 5 minutes. A lifetime above 5 minutes is logged as a warning.
     */
    private Duration idTokenLifetime;

    /**
     * Gets the authorization code lifetime.
     *
     * @return the lifetime, or {@code null} for the default
     */
    public @Nullable Duration getAuthorizationCodeLifetime() {
      return this.authorizationCodeLifetime;
    }

    /**
     * Assigns the authorization code lifetime.
     *
     * @param authorizationCodeLifetime the lifetime
     */
    public void setAuthorizationCodeLifetime(final @Nullable Duration authorizationCodeLifetime) {
      this.authorizationCodeLifetime = authorizationCodeLifetime;
    }

    /**
     * Gets the access token lifetime.
     *
     * @return the lifetime, or {@code null} for the default
     */
    public @Nullable Duration getAccessTokenLifetime() {
      return this.accessTokenLifetime;
    }

    /**
     * Assigns the access token lifetime.
     *
     * @param accessTokenLifetime the lifetime
     */
    public void setAccessTokenLifetime(final @Nullable Duration accessTokenLifetime) {
      this.accessTokenLifetime = accessTokenLifetime;
    }

    /**
     * Gets whether an access token may only be used once.
     *
     * @return whether access tokens are single use, or {@code null} for the default
     */
    public @Nullable Boolean getAccessTokenSingleUse() {
      return this.accessTokenSingleUse;
    }

    /**
     * Assigns whether an access token may only be used once.
     *
     * @param accessTokenSingleUse whether access tokens are single use
     */
    public void setAccessTokenSingleUse(final @Nullable Boolean accessTokenSingleUse) {
      this.accessTokenSingleUse = accessTokenSingleUse;
    }

    /**
     * Gets the ID token lifetime.
     *
     * @return the lifetime, or {@code null} for the default
     */
    public @Nullable Duration getIdTokenLifetime() {
      return this.idTokenLifetime;
    }

    /**
     * Assigns the ID token lifetime.
     *
     * @param idTokenLifetime the lifetime
     */
    public void setIdTokenLifetime(final @Nullable Duration idTokenLifetime) {
      this.idTokenLifetime = idTokenLifetime;
    }
  }

  /**
   * Where each store of the OpenID Provider is kept: "memory" or "redis". A store that is not assigned follows
   * authn-server.storage.type.
   */
  public static class StorageProperties {

    /**
     * Where authorization codes are kept: "memory" or "redis".
     */
    private String authorizationCodes;

    /**
     * Where access tokens are kept: "memory" or "redis".
     */
    private String accessTokens;

    /**
     * Where the jti values of used client assertions (private_key_jwt and client_secret_jwt) are kept: "memory" or
     * "redis".
     */
    private String clientAssertions;

    /**
     * Where the cache of clients resolved through OpenID Federation is kept, together with the lookup counts and the
     * lock of its background jobs: "memory" or "redis".
     */
    private String federationCache;

    /**
     * Where the OpenID Provider's own trust marks and their state are kept: "memory" or "redis".
     */
    private String trustMarks;

    /**
     * Gets where authorization codes are kept.
     *
     * @return the storage type, or {@code null}
     */
    public @Nullable String getAuthorizationCodes() {
      return this.authorizationCodes;
    }

    /**
     * Assigns where authorization codes are kept.
     *
     * @param authorizationCodes the storage type
     */
    public void setAuthorizationCodes(final @Nullable String authorizationCodes) {
      this.authorizationCodes = authorizationCodes;
    }

    /**
     * Gets where access tokens are kept.
     *
     * @return the storage type, or {@code null}
     */
    public @Nullable String getAccessTokens() {
      return this.accessTokens;
    }

    /**
     * Assigns where access tokens are kept.
     *
     * @param accessTokens the storage type
     */
    public void setAccessTokens(final @Nullable String accessTokens) {
      this.accessTokens = accessTokens;
    }

    /**
     * Gets where the values of used client assertions are kept.
     *
     * @return the storage type, or {@code null}
     */
    public @Nullable String getClientAssertions() {
      return this.clientAssertions;
    }

    /**
     * Assigns where the values of used client assertions are kept.
     *
     * @param clientAssertions the storage type
     */
    public void setClientAssertions(final @Nullable String clientAssertions) {
      this.clientAssertions = clientAssertions;
    }

    /**
     * Gets where the federation cache is kept.
     *
     * @return the storage type, or {@code null}
     */
    public @Nullable String getFederationCache() {
      return this.federationCache;
    }

    /**
     * Assigns where the federation cache is kept.
     *
     * @param federationCache the storage type
     */
    public void setFederationCache(final @Nullable String federationCache) {
      this.federationCache = federationCache;
    }

    /**
     * Gets where the OpenID Provider's own trust marks are kept.
     *
     * @return the storage type, or {@code null}
     */
    public @Nullable String getTrustMarks() {
      return this.trustMarks;
    }

    /**
     * Assigns where the OpenID Provider's own trust marks are kept.
     *
     * @param trustMarks the storage type
     */
    public void setTrustMarks(final @Nullable String trustMarks) {
      this.trustMarks = trustMarks;
    }
  }

}
