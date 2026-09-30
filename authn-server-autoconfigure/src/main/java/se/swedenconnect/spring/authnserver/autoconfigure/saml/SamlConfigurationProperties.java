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
package se.swedenconnect.spring.authnserver.autoconfigure.saml;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;

import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;
import java.util.Map;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.io.Resource;

import se.swedenconnect.security.credential.config.properties.PkiCredentialConfigurationProperties;
import se.swedenconnect.spring.authnserver.autoconfigure.AuthnServerConfigurationProperties.SsoProperties;
import se.swedenconnect.spring.authnserver.autoconfigure.AuthnServerConfigurationProperties.SubjectIdentifierProperties;
import se.swedenconnect.spring.authnserver.saml.config.IdpMetadataElements.ContactPersonType;

/**
 * Configuration properties for the SAML Identity Provider.
 *
 * @author Martin Lindström
 */
@ConfigurationProperties(SamlConfigurationProperties.PREFIX)
public class SamlConfigurationProperties {

  /** The property prefix. */
  public static final String PREFIX = "authn-server.saml";

  /**
   * Whether the SAML Identity Provider is enabled. Defaults to false.
   */
  private boolean enabled = false;

  /**
   * The SAML path, relative to the base URL. The SAML endpoints are placed under it. Defaults to /saml2.
   */
  private String path;

  /**
   * The SAML entity ID of the Identity Provider. Defaults to the base URL.
   */
  private String entityId;

  /**
   * The base URL for Holder-of-key endpoints, when Holder-of-key needs another host or port than the base URL. Must
   * not end with a '/'.
   */
  private String hokBaseUrl;

  /**
   * Whether the Identity Provider requires signed authentication requests. Defaults to true.
   */
  private Boolean requiresSignedRequests;

  /**
   * Single sign-on policy for SAML. Unassigned values are taken from authn-server.sso.
   */
  private final SsoProperties sso = new SsoProperties();

  /**
   * Clock skew for SAML. Overrides authn-server.clock-skew.
   */
  private Duration clockSkew;

  /**
   * Whether user messages are supported for SAML. Overrides authn-server.supports-user-message.
   */
  private Boolean supportsUserMessage;

  /**
   * Subject identifier settings for SAML. Overrides authn-server.subject-identifier.
   */
  private final SubjectIdentifierProperties subjectIdentifier = new SubjectIdentifierProperties();

  /**
   * The Identity Provider credentials.
   */
  private final CredentialProperties credentials = new CredentialProperties();

  /**
   * The SAML endpoints, relative to the SAML path.
   */
  private final EndpointProperties endpoints = new EndpointProperties();

  /**
   * The metadata that the Identity Provider publishes.
   */
  private final MetadataProperties metadata = new MetadataProperties();

  /**
   * Gets whether the SAML Identity Provider is enabled.
   *
   * @return whether the SAML Identity Provider is enabled
   */
  public boolean isEnabled() {
    return this.enabled;
  }

  /**
   * Assigns whether the SAML Identity Provider is enabled.
   *
   * @param enabled whether the SAML Identity Provider is enabled
   */
  public void setEnabled(final boolean enabled) {
    this.enabled = enabled;
  }

  /**
   * Gets the SAML path.
   *
   * @return the SAML path
   */
  public @Nullable String getPath() {
    return this.path;
  }

  /**
   * Assigns the SAML path.
   *
   * @param path the SAML path
   */
  public void setPath(final @Nullable String path) {
    this.path = path;
  }

  /**
   * Gets the SAML entity ID.
   *
   * @return the SAML entity ID
   */
  public @Nullable String getEntityId() {
    return this.entityId;
  }

  /**
   * Assigns the SAML entity ID.
   *
   * @param entityId the SAML entity ID
   */
  public void setEntityId(final @Nullable String entityId) {
    this.entityId = entityId;
  }

  /**
   * Gets the Holder-of-key base URL.
   *
   * @return the Holder-of-key base URL
   */
  public @Nullable String getHokBaseUrl() {
    return this.hokBaseUrl;
  }

  /**
   * Assigns the Holder-of-key base URL.
   *
   * @param hokBaseUrl the Holder-of-key base URL
   */
  public void setHokBaseUrl(final @Nullable String hokBaseUrl) {
    this.hokBaseUrl = hokBaseUrl;
  }

  /**
   * Gets whether signed authentication requests are required.
   *
   * @return whether signed authentication requests are required
   */
  public @Nullable Boolean getRequiresSignedRequests() {
    return this.requiresSignedRequests;
  }

  /**
   * Assigns whether signed authentication requests are required.
   *
   * @param requiresSignedRequests whether signed authentication requests are required
   */
  public void setRequiresSignedRequests(final @Nullable Boolean requiresSignedRequests) {
    this.requiresSignedRequests = requiresSignedRequests;
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
   * Gets the credential properties.
   *
   * @return the credential properties
   */
  public @Nonnull CredentialProperties getCredentials() {
    return this.credentials;
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
   * Gets the metadata properties.
   *
   * @return the metadata properties
   */
  public @Nonnull MetadataProperties getMetadata() {
    return this.metadata;
  }

  /**
   * Configuration properties for the Identity Provider credentials.
   */
  public static class CredentialProperties {

    /**
     * The default credential. Used for signing, encryption and metadata signing when no specific credential is
     * assigned for that use.
     */
    private PkiCredentialConfigurationProperties defaultCredential;

    /**
     * The credential that the Identity Provider signs responses and assertions with.
     */
    private PkiCredentialConfigurationProperties sign;

    /**
     * A certificate that will be the future signing certificate. Is set before a key rollover is performed.
     */
    private X509Certificate futureSign;

    /**
     * The encryption credential. Service Providers encrypt data for the Identity Provider with its certificate.
     */
    private PkiCredentialConfigurationProperties encrypt;

    /**
     * The previous encryption credential. Assigned after a key rollover.
     */
    private PkiCredentialConfigurationProperties previousEncrypt;

    /**
     * The credential that the Identity Provider signs its metadata with.
     */
    private PkiCredentialConfigurationProperties metadataSign;

    /**
     * Gets the default credential.
     *
     * @return the default credential
     */
    public @Nullable PkiCredentialConfigurationProperties getDefaultCredential() {
      return this.defaultCredential;
    }

    /**
     * Assigns the default credential.
     *
     * @param defaultCredential the default credential
     */
    public void setDefaultCredential(final @Nullable PkiCredentialConfigurationProperties defaultCredential) {
      this.defaultCredential = defaultCredential;
    }

    /**
     * Gets the signing credential.
     *
     * @return the signing credential
     */
    public @Nullable PkiCredentialConfigurationProperties getSign() {
      return this.sign;
    }

    /**
     * Assigns the signing credential.
     *
     * @param sign the signing credential
     */
    public void setSign(final @Nullable PkiCredentialConfigurationProperties sign) {
      this.sign = sign;
    }

    /**
     * Gets the future signing certificate.
     *
     * @return the future signing certificate
     */
    public @Nullable X509Certificate getFutureSign() {
      return this.futureSign;
    }

    /**
     * Assigns the future signing certificate.
     *
     * @param futureSign the future signing certificate
     */
    public void setFutureSign(final @Nullable X509Certificate futureSign) {
      this.futureSign = futureSign;
    }

    /**
     * Gets the encryption credential.
     *
     * @return the encryption credential
     */
    public @Nullable PkiCredentialConfigurationProperties getEncrypt() {
      return this.encrypt;
    }

    /**
     * Assigns the encryption credential.
     *
     * @param encrypt the encryption credential
     */
    public void setEncrypt(final @Nullable PkiCredentialConfigurationProperties encrypt) {
      this.encrypt = encrypt;
    }

    /**
     * Gets the previous encryption credential.
     *
     * @return the previous encryption credential
     */
    public @Nullable PkiCredentialConfigurationProperties getPreviousEncrypt() {
      return this.previousEncrypt;
    }

    /**
     * Assigns the previous encryption credential.
     *
     * @param previousEncrypt the previous encryption credential
     */
    public void setPreviousEncrypt(final @Nullable PkiCredentialConfigurationProperties previousEncrypt) {
      this.previousEncrypt = previousEncrypt;
    }

    /**
     * Gets the metadata signing credential.
     *
     * @return the metadata signing credential
     */
    public @Nullable PkiCredentialConfigurationProperties getMetadataSign() {
      return this.metadataSign;
    }

    /**
     * Assigns the metadata signing credential.
     *
     * @param metadataSign the metadata signing credential
     */
    public void setMetadataSign(final @Nullable PkiCredentialConfigurationProperties metadataSign) {
      this.metadataSign = metadataSign;
    }
  }

  /**
   * Configuration properties for the SAML endpoints, relative to the SAML path.
   */
  public static class EndpointProperties {

    /**
     * The endpoint where authentication requests are received with the redirect binding. Defaults to /redirect/authn.
     */
    private String redirectAuthn;

    /**
     * The endpoint where authentication requests are received with the POST binding. Defaults to /post/authn.
     */
    private String postAuthn;

    /**
     * The endpoint where authentication requests are received with the redirect binding and Holder-of-key. Not
     * offered unless assigned.
     */
    private String hokRedirectAuthn;

    /**
     * The endpoint where authentication requests are received with the POST binding and Holder-of-key. Not offered
     * unless assigned.
     */
    private String hokPostAuthn;

    /**
     * The endpoint where the metadata is published. Defaults to /metadata.
     */
    private String metadata;

    /**
     * Gets the redirect binding authentication endpoint.
     *
     * @return the redirect binding authentication endpoint
     */
    public @Nullable String getRedirectAuthn() {
      return this.redirectAuthn;
    }

    /**
     * Assigns the redirect binding authentication endpoint.
     *
     * @param redirectAuthn the redirect binding authentication endpoint
     */
    public void setRedirectAuthn(final @Nullable String redirectAuthn) {
      this.redirectAuthn = redirectAuthn;
    }

    /**
     * Gets the POST binding authentication endpoint.
     *
     * @return the POST binding authentication endpoint
     */
    public @Nullable String getPostAuthn() {
      return this.postAuthn;
    }

    /**
     * Assigns the POST binding authentication endpoint.
     *
     * @param postAuthn the POST binding authentication endpoint
     */
    public void setPostAuthn(final @Nullable String postAuthn) {
      this.postAuthn = postAuthn;
    }

    /**
     * Gets the Holder-of-key redirect binding authentication endpoint.
     *
     * @return the Holder-of-key redirect binding authentication endpoint
     */
    public @Nullable String getHokRedirectAuthn() {
      return this.hokRedirectAuthn;
    }

    /**
     * Assigns the Holder-of-key redirect binding authentication endpoint.
     *
     * @param hokRedirectAuthn the Holder-of-key redirect binding authentication endpoint
     */
    public void setHokRedirectAuthn(final @Nullable String hokRedirectAuthn) {
      this.hokRedirectAuthn = hokRedirectAuthn;
    }

    /**
     * Gets the Holder-of-key POST binding authentication endpoint.
     *
     * @return the Holder-of-key POST binding authentication endpoint
     */
    public @Nullable String getHokPostAuthn() {
      return this.hokPostAuthn;
    }

    /**
     * Assigns the Holder-of-key POST binding authentication endpoint.
     *
     * @param hokPostAuthn the Holder-of-key POST binding authentication endpoint
     */
    public void setHokPostAuthn(final @Nullable String hokPostAuthn) {
      this.hokPostAuthn = hokPostAuthn;
    }

    /**
     * Gets the metadata publishing endpoint.
     *
     * @return the metadata publishing endpoint
     */
    public @Nullable String getMetadata() {
      return this.metadata;
    }

    /**
     * Assigns the metadata publishing endpoint.
     *
     * @param metadata the metadata publishing endpoint
     */
    public void setMetadata(final @Nullable String metadata) {
      this.metadata = metadata;
    }
  }

  /**
   * Configuration properties for the Identity Provider metadata.
   */
  public static class MetadataProperties {

    /**
     * A template for the metadata.
     */
    private Resource template;

    /**
     * How long the published metadata may be cached. Defaults to 24 hours.
     */
    private Duration cacheDuration;

    /**
     * For how long published metadata is valid. Defaults to 7 days.
     */
    private Duration validityPeriod;

    /**
     * The alg:DigestMethod elements to include in the metadata.
     */
    private List<String> digestMethods;

    /**
     * Whether alg:DigestMethod elements are placed in the Extensions element of the IDPSSODescriptor instead of in
     * the Extensions element of the EntityDescriptor.
     */
    private boolean includeDigestMethodsUnderRole = false;

    /**
     * The alg:SigningMethod elements to include in the metadata.
     */
    private List<SigningMethod> signingMethods;

    /**
     * Whether alg:SigningMethod elements are placed in the Extensions element of the IDPSSODescriptor instead of in
     * the Extensions element of the EntityDescriptor.
     */
    private boolean includeSigningMethodsUnderRole = false;

    /**
     * The md:EncryptionMethod elements to include under the md:KeyDescriptor of the encryption key. They must match
     * the encryption key.
     */
    private List<EncryptionMethod> encryptionMethods;

    /**
     * The mdui:UIInfo element.
     */
    private UiInfo uiInfo;

    /**
     * Attribute names to include in the RequestedPrincipalSelection metadata extension.
     */
    private List<String> requestedPrincipalSelection;

    /**
     * The md:Organization element.
     */
    private Organization organization;

    /**
     * The md:ContactPerson elements.
     */
    private Map<ContactPersonType, ContactPerson> contactPersons;

    /**
     * Gets the metadata template.
     *
     * @return the metadata template
     */
    public @Nullable Resource getTemplate() {
      return this.template;
    }

    /**
     * Assigns the metadata template.
     *
     * @param template the metadata template
     */
    public void setTemplate(final @Nullable Resource template) {
      this.template = template;
    }

    /**
     * Gets the cache duration.
     *
     * @return the cache duration
     */
    public @Nullable Duration getCacheDuration() {
      return this.cacheDuration;
    }

    /**
     * Assigns the cache duration.
     *
     * @param cacheDuration the cache duration
     */
    public void setCacheDuration(final @Nullable Duration cacheDuration) {
      this.cacheDuration = cacheDuration;
    }

    /**
     * Gets the validity period.
     *
     * @return the validity period
     */
    public @Nullable Duration getValidityPeriod() {
      return this.validityPeriod;
    }

    /**
     * Assigns the validity period.
     *
     * @param validityPeriod the validity period
     */
    public void setValidityPeriod(final @Nullable Duration validityPeriod) {
      this.validityPeriod = validityPeriod;
    }

    /**
     * Gets the digest methods.
     *
     * @return the digest methods
     */
    public @Nullable List<String> getDigestMethods() {
      return this.digestMethods;
    }

    /**
     * Assigns the digest methods.
     *
     * @param digestMethods the digest methods
     */
    public void setDigestMethods(final @Nullable List<String> digestMethods) {
      this.digestMethods = digestMethods;
    }

    /**
     * Gets whether digest methods are placed under the role descriptor.
     *
     * @return whether digest methods are placed under the role descriptor
     */
    public boolean isIncludeDigestMethodsUnderRole() {
      return this.includeDigestMethodsUnderRole;
    }

    /**
     * Assigns whether digest methods are placed under the role descriptor.
     *
     * @param includeDigestMethodsUnderRole whether digest methods are placed under the role descriptor
     */
    public void setIncludeDigestMethodsUnderRole(final boolean includeDigestMethodsUnderRole) {
      this.includeDigestMethodsUnderRole = includeDigestMethodsUnderRole;
    }

    /**
     * Gets the signing methods.
     *
     * @return the signing methods
     */
    public @Nullable List<SigningMethod> getSigningMethods() {
      return this.signingMethods;
    }

    /**
     * Assigns the signing methods.
     *
     * @param signingMethods the signing methods
     */
    public void setSigningMethods(final @Nullable List<SigningMethod> signingMethods) {
      this.signingMethods = signingMethods;
    }

    /**
     * Gets whether signing methods are placed under the role descriptor.
     *
     * @return whether signing methods are placed under the role descriptor
     */
    public boolean isIncludeSigningMethodsUnderRole() {
      return this.includeSigningMethodsUnderRole;
    }

    /**
     * Assigns whether signing methods are placed under the role descriptor.
     *
     * @param includeSigningMethodsUnderRole whether signing methods are placed under the role descriptor
     */
    public void setIncludeSigningMethodsUnderRole(final boolean includeSigningMethodsUnderRole) {
      this.includeSigningMethodsUnderRole = includeSigningMethodsUnderRole;
    }

    /**
     * Gets the encryption methods.
     *
     * @return the encryption methods
     */
    public @Nullable List<EncryptionMethod> getEncryptionMethods() {
      return this.encryptionMethods;
    }

    /**
     * Assigns the encryption methods.
     *
     * @param encryptionMethods the encryption methods
     */
    public void setEncryptionMethods(final @Nullable List<EncryptionMethod> encryptionMethods) {
      this.encryptionMethods = encryptionMethods;
    }

    /**
     * Gets the UI information.
     *
     * @return the UI information
     */
    public @Nullable UiInfo getUiInfo() {
      return this.uiInfo;
    }

    /**
     * Assigns the UI information.
     *
     * @param uiInfo the UI information
     */
    public void setUiInfo(final @Nullable UiInfo uiInfo) {
      this.uiInfo = uiInfo;
    }

    /**
     * Gets the requested principal selection attribute names.
     *
     * @return the requested principal selection attribute names
     */
    public @Nullable List<String> getRequestedPrincipalSelection() {
      return this.requestedPrincipalSelection;
    }

    /**
     * Assigns the requested principal selection attribute names.
     *
     * @param requestedPrincipalSelection the requested principal selection attribute names
     */
    public void setRequestedPrincipalSelection(final @Nullable List<String> requestedPrincipalSelection) {
      this.requestedPrincipalSelection = requestedPrincipalSelection;
    }

    /**
     * Gets the organisation.
     *
     * @return the organisation
     */
    public @Nullable Organization getOrganization() {
      return this.organization;
    }

    /**
     * Assigns the organisation.
     *
     * @param organization the organisation
     */
    public void setOrganization(final @Nullable Organization organization) {
      this.organization = organization;
    }

    /**
     * Gets the contact persons.
     *
     * @return the contact persons
     */
    public @Nullable Map<ContactPersonType, ContactPerson> getContactPersons() {
      return this.contactPersons;
    }

    /**
     * Assigns the contact persons.
     *
     * @param contactPersons the contact persons
     */
    public void setContactPersons(final @Nullable Map<ContactPersonType, ContactPerson> contactPersons) {
      this.contactPersons = contactPersons;
    }

    /**
     * An alg:SigningMethod element.
     */
    public static class SigningMethod {

      /**
       * The algorithm URI.
       */
      private String algorithm;

      /**
       * The smallest key size, in bits, supported with the algorithm.
       */
      private Integer minKeySize;

      /**
       * The largest key size, in bits, supported with the algorithm.
       */
      private Integer maxKeySize;

      /**
       * Gets the algorithm.
       *
       * @return the algorithm
       */
      public @Nullable String getAlgorithm() {
        return this.algorithm;
      }

      /**
       * Assigns the algorithm.
       *
       * @param algorithm the algorithm
       */
      public void setAlgorithm(final @Nullable String algorithm) {
        this.algorithm = algorithm;
      }

      /**
       * Gets the minimum key size.
       *
       * @return the minimum key size
       */
      public @Nullable Integer getMinKeySize() {
        return this.minKeySize;
      }

      /**
       * Assigns the minimum key size.
       *
       * @param minKeySize the minimum key size
       */
      public void setMinKeySize(final @Nullable Integer minKeySize) {
        this.minKeySize = minKeySize;
      }

      /**
       * Gets the maximum key size.
       *
       * @return the maximum key size
       */
      public @Nullable Integer getMaxKeySize() {
        return this.maxKeySize;
      }

      /**
       * Assigns the maximum key size.
       *
       * @param maxKeySize the maximum key size
       */
      public void setMaxKeySize(final @Nullable Integer maxKeySize) {
        this.maxKeySize = maxKeySize;
      }
    }

    /**
     * An md:EncryptionMethod element.
     */
    public static class EncryptionMethod {

      /**
       * The algorithm URI.
       */
      private String algorithm;

      /**
       * The key size.
       */
      private Integer keySize;

      /**
       * The OAEP parameters, in Base64.
       */
      private String oaepParams;

      /**
       * The digest algorithm URI, for key transport algorithms that need one.
       */
      private String digestMethod;

      /**
       * Gets the algorithm.
       *
       * @return the algorithm
       */
      public @Nullable String getAlgorithm() {
        return this.algorithm;
      }

      /**
       * Assigns the algorithm.
       *
       * @param algorithm the algorithm
       */
      public void setAlgorithm(final @Nullable String algorithm) {
        this.algorithm = algorithm;
      }

      /**
       * Gets the key size.
       *
       * @return the key size
       */
      public @Nullable Integer getKeySize() {
        return this.keySize;
      }

      /**
       * Assigns the key size.
       *
       * @param keySize the key size
       */
      public void setKeySize(final @Nullable Integer keySize) {
        this.keySize = keySize;
      }

      /**
       * Gets the OAEP parameters.
       *
       * @return the OAEP parameters
       */
      public @Nullable String getOaepParams() {
        return this.oaepParams;
      }

      /**
       * Assigns the OAEP parameters.
       *
       * @param oaepParams the OAEP parameters
       */
      public void setOaepParams(final @Nullable String oaepParams) {
        this.oaepParams = oaepParams;
      }

      /**
       * Gets the digest method.
       *
       * @return the digest method
       */
      public @Nullable String getDigestMethod() {
        return this.digestMethod;
      }

      /**
       * Assigns the digest method.
       *
       * @param digestMethod the digest method
       */
      public void setDigestMethod(final @Nullable String digestMethod) {
        this.digestMethod = digestMethod;
      }
    }

    /**
     * The mdui:UIInfo element.
     */
    public static class UiInfo {

      /**
       * Display names, keyed by language tag.
       */
      private Map<String, String> displayNames;

      /**
       * Descriptions, keyed by language tag.
       */
      private Map<String, String> descriptions;

      /**
       * Logotypes.
       */
      private List<Logo> logotypes;

      /**
       * Gets the display names.
       *
       * @return the display names
       */
      public @Nullable Map<String, String> getDisplayNames() {
        return this.displayNames;
      }

      /**
       * Assigns the display names.
       *
       * @param displayNames the display names
       */
      public void setDisplayNames(final @Nullable Map<String, String> displayNames) {
        this.displayNames = displayNames;
      }

      /**
       * Gets the descriptions.
       *
       * @return the descriptions
       */
      public @Nullable Map<String, String> getDescriptions() {
        return this.descriptions;
      }

      /**
       * Assigns the descriptions.
       *
       * @param descriptions the descriptions
       */
      public void setDescriptions(final @Nullable Map<String, String> descriptions) {
        this.descriptions = descriptions;
      }

      /**
       * Gets the logotypes.
       *
       * @return the logotypes
       */
      public @Nullable List<Logo> getLogotypes() {
        return this.logotypes;
      }

      /**
       * Assigns the logotypes.
       *
       * @param logotypes the logotypes
       */
      public void setLogotypes(final @Nullable List<Logo> logotypes) {
        this.logotypes = logotypes;
      }

      /**
       * An mdui:Logo element.
       */
      public static class Logo {

        /**
         * The logotype URL. Mutually exclusive with path.
         */
        private String url;

        /**
         * The logotype path, relative to the base URL. Mutually exclusive with url.
         */
        private String path;

        /**
         * The height in pixels.
         */
        private Integer height;

        /**
         * The width in pixels.
         */
        private Integer width;

        /**
         * The language tag.
         */
        private String languageTag;

        /**
         * Gets the logotype URL.
         *
         * @return the logotype URL
         */
        public @Nullable String getUrl() {
          return this.url;
        }

        /**
         * Assigns the logotype URL.
         *
         * @param url the logotype URL
         */
        public void setUrl(final @Nullable String url) {
          this.url = url;
        }

        /**
         * Gets the logotype path.
         *
         * @return the logotype path
         */
        public @Nullable String getPath() {
          return this.path;
        }

        /**
         * Assigns the logotype path.
         *
         * @param path the logotype path
         */
        public void setPath(final @Nullable String path) {
          this.path = path;
        }

        /**
         * Gets the height.
         *
         * @return the height
         */
        public @Nullable Integer getHeight() {
          return this.height;
        }

        /**
         * Assigns the height.
         *
         * @param height the height
         */
        public void setHeight(final @Nullable Integer height) {
          this.height = height;
        }

        /**
         * Gets the width.
         *
         * @return the width
         */
        public @Nullable Integer getWidth() {
          return this.width;
        }

        /**
         * Assigns the width.
         *
         * @param width the width
         */
        public void setWidth(final @Nullable Integer width) {
          this.width = width;
        }

        /**
         * Gets the language tag.
         *
         * @return the language tag
         */
        public @Nullable String getLanguageTag() {
          return this.languageTag;
        }

        /**
         * Assigns the language tag.
         *
         * @param languageTag the language tag
         */
        public void setLanguageTag(final @Nullable String languageTag) {
          this.languageTag = languageTag;
        }
      }
    }

    /**
     * The md:Organization element.
     */
    public static class Organization {

      /**
       * OrganizationName elements, keyed by language tag.
       */
      private Map<String, String> names;

      /**
       * OrganizationDisplayName elements, keyed by language tag.
       */
      private Map<String, String> displayNames;

      /**
       * OrganizationURL elements, keyed by language tag.
       */
      private Map<String, String> urls;

      /**
       * The organisation number, published as mdorgext:OrganizationNumber.
       */
      private String number;

      /**
       * Gets the organisation names.
       *
       * @return the organisation names
       */
      public @Nullable Map<String, String> getNames() {
        return this.names;
      }

      /**
       * Assigns the organisation names.
       *
       * @param names the organisation names
       */
      public void setNames(final @Nullable Map<String, String> names) {
        this.names = names;
      }

      /**
       * Gets the organisation display names.
       *
       * @return the organisation display names
       */
      public @Nullable Map<String, String> getDisplayNames() {
        return this.displayNames;
      }

      /**
       * Assigns the organisation display names.
       *
       * @param displayNames the organisation display names
       */
      public void setDisplayNames(final @Nullable Map<String, String> displayNames) {
        this.displayNames = displayNames;
      }

      /**
       * Gets the organisation URLs.
       *
       * @return the organisation URLs
       */
      public @Nullable Map<String, String> getUrls() {
        return this.urls;
      }

      /**
       * Assigns the organisation URLs.
       *
       * @param urls the organisation URLs
       */
      public void setUrls(final @Nullable Map<String, String> urls) {
        this.urls = urls;
      }

      /**
       * Gets the organisation number.
       *
       * @return the organisation number
       */
      public @Nullable String getNumber() {
        return this.number;
      }

      /**
       * Assigns the organisation number.
       *
       * @param number the organisation number
       */
      public void setNumber(final @Nullable String number) {
        this.number = number;
      }
    }

    /**
     * An md:ContactPerson element.
     */
    public static class ContactPerson {

      /**
       * The Company element.
       */
      private String company;

      /**
       * The GivenName element.
       */
      private String givenName;

      /**
       * The SurName element.
       */
      private String surname;

      /**
       * The EmailAddress elements.
       */
      private List<String> emailAddresses;

      /**
       * The TelephoneNumber elements.
       */
      private List<String> telephoneNumbers;

      /**
       * Gets the company.
       *
       * @return the company
       */
      public @Nullable String getCompany() {
        return this.company;
      }

      /**
       * Assigns the company.
       *
       * @param company the company
       */
      public void setCompany(final @Nullable String company) {
        this.company = company;
      }

      /**
       * Gets the given name.
       *
       * @return the given name
       */
      public @Nullable String getGivenName() {
        return this.givenName;
      }

      /**
       * Assigns the given name.
       *
       * @param givenName the given name
       */
      public void setGivenName(final @Nullable String givenName) {
        this.givenName = givenName;
      }

      /**
       * Gets the surname.
       *
       * @return the surname
       */
      public @Nullable String getSurname() {
        return this.surname;
      }

      /**
       * Assigns the surname.
       *
       * @param surname the surname
       */
      public void setSurname(final @Nullable String surname) {
        this.surname = surname;
      }

      /**
       * Gets the e-mail addresses.
       *
       * @return the e-mail addresses
       */
      public @Nullable List<String> getEmailAddresses() {
        return this.emailAddresses;
      }

      /**
       * Assigns the e-mail addresses.
       *
       * @param emailAddresses the e-mail addresses
       */
      public void setEmailAddresses(final @Nullable List<String> emailAddresses) {
        this.emailAddresses = emailAddresses;
      }

      /**
       * Gets the telephone numbers.
       *
       * @return the telephone numbers
       */
      public @Nullable List<String> getTelephoneNumbers() {
        return this.telephoneNumbers;
      }

      /**
       * Assigns the telephone numbers.
       *
       * @param telephoneNumbers the telephone numbers
       */
      public void setTelephoneNumbers(final @Nullable List<String> telephoneNumbers) {
        this.telephoneNumbers = telephoneNumbers;
      }
    }
  }

}
