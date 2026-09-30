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

import java.io.IOException;
import java.io.InputStream;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import javax.xml.namespace.QName;

import net.shibboleth.shared.xml.XMLParserException;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.ext.saml2alg.DigestMethod;
import org.opensaml.saml.ext.saml2alg.SigningMethod;
import org.opensaml.saml.ext.saml2mdattr.EntityAttributes;
import org.opensaml.saml.ext.saml2mdui.UIInfo;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.metadata.ContactPerson;
import org.opensaml.saml.saml2.metadata.ContactPersonTypeEnumeration;
import org.opensaml.saml.saml2.metadata.EncryptionMethod;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.Extensions;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.x509.X509Credential;
import org.opensaml.xmlsec.encryption.KeySize;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;

import se.swedenconnect.opensaml.common.utils.LocalizedString;
import se.swedenconnect.opensaml.saml2.metadata.EntityDescriptorContainer;
import se.swedenconnect.opensaml.saml2.metadata.EntityDescriptorUtils;
import se.swedenconnect.opensaml.saml2.metadata.build.ContactPersonBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.DigestMethodBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.EncryptionMethodBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.EntityAttributesBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.EntityDescriptorBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.IDPSSODescriptorBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.KeyDescriptorBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.LogoBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.OrganizationBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.SigningMethodBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.SingleSignOnServiceBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.UIInfoBuilder;
import se.swedenconnect.opensaml.sweid.saml2.authn.psc.RequestedPrincipalSelection;
import se.swedenconnect.opensaml.sweid.saml2.authn.psc.build.MatchValueBuilder;
import se.swedenconnect.opensaml.sweid.saml2.authn.psc.build.RequestedPrincipalSelectionBuilder;
import se.swedenconnect.opensaml.sweid.saml2.metadata.entitycategory.EntityCategoryConstants;
import se.swedenconnect.opensaml.sweid.saml2.metadata.ext.OrganizationNumber;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.opensaml.OpenSamlCredential;
import se.swedenconnect.spring.authnserver.authentication.provider.UserAuthenticationProvider;
import se.swedenconnect.spring.authnserver.saml.config.IdpMetadataElements.ContactPersonType;
import se.swedenconnect.spring.authnserver.saml.web.Saml2IdpMetadataEndpointFilter;

/**
 * Configurer for the metadata that the SAML Identity Provider publishes, and for the endpoint that publishes it.
 * <p>
 * The metadata is built from the values of this configurer and of the {@link Saml2IdpConfigurer}: the entity ID, the
 * endpoints, the credentials and whether signed requests are wanted. The assurance certification and entity category
 * attributes are the authentication context URIs and entity categories of the authentication providers. A template
 * may be given, and the values here are then added to it or replace what it holds.
 * </p>
 *
 * @author Martin Lindström
 */
public class Saml2IdpMetadataEndpointConfigurer {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(Saml2IdpMetadataEndpointConfigurer.class);

  /** The default cache duration of the metadata, 24 hours. */
  public static final Duration DEFAULT_CACHE_DURATION = Duration.ofHours(24);

  /** The default validity period of the metadata, 7 days. */
  public static final Duration DEFAULT_VALIDITY_PERIOD = Duration.ofDays(7);

  /** The SAML configurer. */
  private final Saml2IdpConfigurer samlConfigurer;

  /** The metadata template. */
  private Resource template;

  /** The cache duration. */
  private Duration cacheDuration = DEFAULT_CACHE_DURATION;

  /** The validity period. */
  private Duration validityPeriod = DEFAULT_VALIDITY_PERIOD;

  /** The digest methods. */
  private List<String> digestMethods;

  /** Whether the digest methods are placed under the role descriptor. */
  private boolean digestMethodsUnderRole = false;

  /** The signing methods. */
  private List<IdpMetadataElements.SigningMethod> signingMethods;

  /** Whether the signing methods are placed under the role descriptor. */
  private boolean signingMethodsUnderRole = false;

  /** The encryption methods. */
  private List<IdpMetadataElements.EncryptionMethod> encryptionMethods;

  /** The UI information. */
  private IdpMetadataElements.UiInfo uiInfo;

  /** The attribute names for the RequestedPrincipalSelection extension. */
  private List<String> requestedPrincipalSelection;

  /** The organisation. */
  private IdpMetadataElements.Organization organization;

  /** The contact persons. */
  private Map<ContactPersonType, IdpMetadataElements.ContactPerson> contactPersons;

  /** For customizing the metadata once it has been built. */
  private Customizer<EntityDescriptor> entityDescriptorCustomizer = Customizer.withDefaults();

  /** The request matcher for the metadata endpoint. */
  private RequestMatcher requestMatcher;

  /**
   * Constructor.
   *
   * @param samlConfigurer the SAML configurer
   */
  Saml2IdpMetadataEndpointConfigurer(final @Nonnull Saml2IdpConfigurer samlConfigurer) {
    this.samlConfigurer = samlConfigurer;
  }

  /**
   * Assigns a template for the metadata. Values of the configurers are added to it or replace what it holds.
   *
   * @param template the template, or {@code null}
   * @return this configurer
   */
  public @Nonnull Saml2IdpMetadataEndpointConfigurer template(final @Nullable Resource template) {
    this.template = template;
    return this;
  }

  /**
   * Assigns how long the metadata may be cached. Defaults to {@link #DEFAULT_CACHE_DURATION}.
   *
   * @param cacheDuration the cache duration
   * @return this configurer
   */
  public @Nonnull Saml2IdpMetadataEndpointConfigurer cacheDuration(final @Nonnull Duration cacheDuration) {
    this.cacheDuration = Objects.requireNonNull(cacheDuration, "cacheDuration must not be null");
    return this;
  }

  /**
   * Assigns for how long published metadata is valid. Defaults to {@link #DEFAULT_VALIDITY_PERIOD}.
   *
   * @param validityPeriod the validity period
   * @return this configurer
   */
  public @Nonnull Saml2IdpMetadataEndpointConfigurer validityPeriod(final @Nonnull Duration validityPeriod) {
    this.validityPeriod = Objects.requireNonNull(validityPeriod, "validityPeriod must not be null");
    return this;
  }

  /**
   * Assigns the {@code alg:DigestMethod} elements. When assigned, they replace those of the template.
   *
   * @param digestMethods the digest algorithm URIs, or {@code null}
   * @return this configurer
   */
  public @Nonnull Saml2IdpMetadataEndpointConfigurer digestMethods(final @Nullable List<String> digestMethods) {
    this.digestMethods = digestMethods;
    return this;
  }

  /**
   * Assigns whether the {@code alg:DigestMethod} elements are placed under the {@code IDPSSODescriptor} instead of
   * under the {@code EntityDescriptor}. Defaults to {@code false}.
   *
   * @param underRole whether the elements are placed under the role descriptor
   * @return this configurer
   */
  public @Nonnull Saml2IdpMetadataEndpointConfigurer digestMethodsUnderRole(final boolean underRole) {
    this.digestMethodsUnderRole = underRole;
    return this;
  }

  /**
   * Assigns the {@code alg:SigningMethod} elements. When assigned, they replace those of the template.
   *
   * @param signingMethods the signing methods, or {@code null}
   * @return this configurer
   */
  public @Nonnull Saml2IdpMetadataEndpointConfigurer signingMethods(
      final @Nullable List<IdpMetadataElements.SigningMethod> signingMethods) {
    this.signingMethods = signingMethods;
    return this;
  }

  /**
   * Assigns whether the {@code alg:SigningMethod} elements are placed under the {@code IDPSSODescriptor} instead of
   * under the {@code EntityDescriptor}. Defaults to {@code false}.
   *
   * @param underRole whether the elements are placed under the role descriptor
   * @return this configurer
   */
  public @Nonnull Saml2IdpMetadataEndpointConfigurer signingMethodsUnderRole(final boolean underRole) {
    this.signingMethodsUnderRole = underRole;
    return this;
  }

  /**
   * Assigns the {@code md:EncryptionMethod} elements of the encryption key. They must match the encryption key.
   *
   * @param encryptionMethods the encryption methods, or {@code null}
   * @return this configurer
   */
  public @Nonnull Saml2IdpMetadataEndpointConfigurer encryptionMethods(
      final @Nullable List<IdpMetadataElements.EncryptionMethod> encryptionMethods) {
    this.encryptionMethods = encryptionMethods;
    return this;
  }

  /**
   * Assigns the {@code mdui:UIInfo} element. When assigned, it replaces that of the template.
   *
   * @param uiInfo the UI information, or {@code null}
   * @return this configurer
   */
  public @Nonnull Saml2IdpMetadataEndpointConfigurer uiInfo(final @Nullable IdpMetadataElements.UiInfo uiInfo) {
    this.uiInfo = uiInfo;
    return this;
  }

  /**
   * Assigns the attribute names of the {@code psc:RequestedPrincipalSelection} extension.
   *
   * @param attributeNames the SAML attribute names, or {@code null}
   * @return this configurer
   */
  public @Nonnull Saml2IdpMetadataEndpointConfigurer requestedPrincipalSelection(
      final @Nullable List<String> attributeNames) {
    this.requestedPrincipalSelection = attributeNames;
    return this;
  }

  /**
   * Assigns the {@code md:Organization} element.
   *
   * @param organization the organisation, or {@code null}
   * @return this configurer
   */
  public @Nonnull Saml2IdpMetadataEndpointConfigurer organization(
      final @Nullable IdpMetadataElements.Organization organization) {
    this.organization = organization;
    return this;
  }

  /**
   * Assigns the {@code md:ContactPerson} elements.
   *
   * @param contactPersons the contact persons, keyed by type, or {@code null}
   * @return this configurer
   */
  public @Nonnull Saml2IdpMetadataEndpointConfigurer contactPersons(
      final @Nullable Map<ContactPersonType, IdpMetadataElements.ContactPerson> contactPersons) {
    this.contactPersons = contactPersons;
    return this;
  }

  /**
   * Assigns a customizer that gets the built {@link EntityDescriptor} before it is signed and published.
   *
   * @param customizer the customizer
   * @return this configurer
   */
  public @Nonnull Saml2IdpMetadataEndpointConfigurer entityDescriptorCustomizer(
      final @Nonnull Customizer<EntityDescriptor> customizer) {
    this.entityDescriptorCustomizer = Objects.requireNonNull(customizer, "customizer must not be null");
    return this;
  }

  /**
   * Initializes the configurer.
   */
  void init() {
    if (this.cacheDuration.isNegative()) {
      throw new IllegalArgumentException("SAML metadata cache duration must not be negative");
    }
    if (this.validityPeriod.isNegative() || this.validityPeriod.isZero()) {
      throw new IllegalArgumentException("SAML metadata validity period must be positive");
    }
    if (this.uiInfo != null && this.uiInfo.logotypes() != null) {
      for (final IdpMetadataElements.Logo logo : this.uiInfo.logotypes()) {
        if ((logo.url() == null) == (logo.path() == null)) {
          throw new IllegalArgumentException("A SAML metadata logotype must have exactly one of url and path");
        }
      }
    }
    this.requestMatcher = PathPatternRequestMatcher.pathPattern(HttpMethod.GET,
        this.samlConfigurer.getEndpointPath(this.samlConfigurer.getMetadataEndpoint()));
  }

  /**
   * Builds the metadata and adds the filter that publishes it.
   *
   * @param http the HTTP security object
   */
  void configure(final @Nonnull HttpSecurity http) {
    final Saml2IdpMetadataEndpointFilter filter =
        new Saml2IdpMetadataEndpointFilter(this.createEntityDescriptorContainer(), this.requestMatcher);
    http.addFilterBefore(this.samlConfigurer.postProcessObject(filter),
        AbstractPreAuthenticatedProcessingFilter.class);
  }

  /**
   * Gets the request matcher for the metadata endpoint.
   *
   * @return the request matcher
   */
  @Nonnull
  RequestMatcher getRequestMatcher() {
    return Objects.requireNonNull(this.requestMatcher, "The configurer has not been initialized");
  }

  /**
   * Builds the metadata and puts it in a container that signs it and keeps it up to date.
   *
   * @return an {@link EntityDescriptorContainer}
   */
  @Nonnull
  EntityDescriptorContainer createEntityDescriptorContainer() {
    final EntityDescriptorBuilder entityDescriptorBuilder = this.buildEntityDescriptor();
    this.entityDescriptorCustomizer.customize(entityDescriptorBuilder.object());

    final PkiCredential metadataSignCredential = this.samlConfigurer.getMetadataSignCredential();
    final X509Credential metadataSigning;
    if (metadataSignCredential != null) {
      metadataSigning = new OpenSamlCredential(metadataSignCredential);
    }
    else {
      log.warn("No SAML metadata signing credential configured - IdP metadata will not be signed");
      metadataSigning = null;
    }
    final EntityDescriptorContainer container =
        new EntityDescriptorContainer(entityDescriptorBuilder.build(), metadataSigning);
    container.setValidity(this.validityPeriod);
    return container;
  }

  /**
   * Builds the metadata.
   *
   * @return a builder holding the metadata
   */
  private @Nonnull EntityDescriptorBuilder buildEntityDescriptor() {
    final Saml2IdpConfigurer saml = this.samlConfigurer;
    final Collection<UserAuthenticationProvider> providers = saml.getServer().getAuthenticationProviders();

    try {
      final EntityDescriptorBuilder builder;
      if (this.template != null) {
        try (final InputStream is = this.template.getInputStream()) {
          final EntityDescriptor template = (EntityDescriptor) XMLObjectSupport.unmarshallFromInputStream(
              Objects.requireNonNull(XMLObjectProviderRegistrySupport.getParserPool()), is);
          builder = new EntityDescriptorBuilder(template);
        }
      }
      else {
        builder = new EntityDescriptorBuilder();
      }
      builder.entityID(saml.getEntityId());
      builder.cacheDuration(this.cacheDuration);

      final Extensions extensions = Optional.ofNullable(builder.object().getExtensions())
          .orElseGet(() -> {
            final Extensions e = (Extensions) XMLObjectSupport.buildXMLObject(Extensions.DEFAULT_ELEMENT_NAME);
            builder.extensions(e);
            return e;
          });

      // EntityAttributes
      //
      final EntityAttributesBuilder entityAttributesBuilder = EntityAttributesBuilder.builder();
      final EntityAttributes entityAttributes =
          EntityDescriptorUtils.getMetadataExtension(extensions, EntityAttributes.class);
      if (entityAttributes != null) {
        entityAttributesBuilder.attributes(entityAttributes.getAttributes());
        extensions.getUnknownXMLObjects().removeIf(o -> EntityAttributes.class.isAssignableFrom(o.getClass()));
      }

      final List<String> authnContextUris = providers.stream()
          .map(UserAuthenticationProvider::getSupportedAuthnContextUris)
          .flatMap(Collection::stream)
          .distinct()
          .toList();
      if (!authnContextUris.isEmpty()) {
        entityAttributesBuilder.assuranceCertificationAttribute(authnContextUris);
      }
      final List<String> entityCategories = new ArrayList<>();
      providers.stream()
          .map(UserAuthenticationProvider::getEntityCategories)
          .flatMap(Collection::stream)
          .distinct()
          .forEach(entityCategories::add);
      if (!entityCategories.isEmpty()) {
        if (saml.isSupportsUserMessage() && !entityCategories.contains(
            EntityCategoryConstants.GENERAL_CATEGORY_SUPPORTS_USER_MESSAGE.getUri())) {
          entityCategories.add(EntityCategoryConstants.GENERAL_CATEGORY_SUPPORTS_USER_MESSAGE.getUri());
        }
        entityAttributesBuilder.entityCategoriesAttribute(entityCategories);
      }

      extensions.getUnknownXMLObjects().add(entityAttributesBuilder.build());

      if (this.digestMethods != null && !this.digestMethodsUnderRole) {
        extensions.getUnknownXMLObjects().removeIf(o -> DigestMethod.class.isAssignableFrom(o.getClass()));
        this.digestMethods.stream()
            .filter(StringUtils::hasText)
            .forEach(d -> extensions.getUnknownXMLObjects().add(DigestMethodBuilder.builder().algorithm(d).build()));
      }
      if (this.signingMethods != null && !this.signingMethodsUnderRole) {
        extensions.getUnknownXMLObjects().removeIf(o -> SigningMethod.class.isAssignableFrom(o.getClass()));
        this.signingMethods.stream()
            .filter(s -> StringUtils.hasText(s.algorithm()))
            .forEach(s -> extensions.getUnknownXMLObjects().add(
                SigningMethodBuilder.signingMethod(s.algorithm(), s.minKeySize(), s.maxKeySize())));
      }

      final IDPSSODescriptor existingSsoDescriptor =
          builder.object().getIDPSSODescriptor(SAMLConstants.SAML20P_NS);
      final IDPSSODescriptorBuilder descBuilder = existingSsoDescriptor != null
          ? new IDPSSODescriptorBuilder(existingSsoDescriptor, true)
          : new IDPSSODescriptorBuilder();

      descBuilder.wantAuthnRequestsSigned(saml.isRequiresSignedRequests());

      final Extensions roleExtensions = Optional.ofNullable(descBuilder.object().getExtensions())
          .orElseGet(() -> (Extensions) XMLObjectSupport.buildXMLObject(Extensions.DEFAULT_ELEMENT_NAME));

      final UIInfo uiInfoElement = this.buildUiInfo();
      if (uiInfoElement != null) {
        roleExtensions.getUnknownXMLObjects().removeIf(o -> UIInfo.class.isAssignableFrom(o.getClass()));
        roleExtensions.getUnknownXMLObjects().add(uiInfoElement);
      }

      if (this.requestedPrincipalSelection != null && !this.requestedPrincipalSelection.isEmpty()) {
        roleExtensions.getUnknownXMLObjects()
            .removeIf(o -> RequestedPrincipalSelection.class.isAssignableFrom(o.getClass()));

        final RequestedPrincipalSelection rps = RequestedPrincipalSelectionBuilder.builder()
            .matchValues(this.requestedPrincipalSelection.stream()
                .map(a -> MatchValueBuilder.builder().name(a).build())
                .toList())
            .build();
        roleExtensions.getUnknownXMLObjects().add(rps);
      }

      if (this.digestMethods != null && this.digestMethodsUnderRole) {
        roleExtensions.getUnknownXMLObjects().removeIf(o -> DigestMethod.class.isAssignableFrom(o.getClass()));
        this.digestMethods.stream()
            .filter(StringUtils::hasText)
            .forEach(
                d -> roleExtensions.getUnknownXMLObjects().add(DigestMethodBuilder.builder().algorithm(d).build()));
      }
      if (this.signingMethods != null && this.signingMethodsUnderRole) {
        roleExtensions.getUnknownXMLObjects().removeIf(o -> SigningMethod.class.isAssignableFrom(o.getClass()));
        this.signingMethods.stream()
            .filter(s -> StringUtils.hasText(s.algorithm()))
            .forEach(s -> roleExtensions.getUnknownXMLObjects().add(
                SigningMethodBuilder.signingMethod(s.algorithm(), s.minKeySize(), s.maxKeySize())));
      }

      if (descBuilder.object().getExtensions() == null && !roleExtensions.getUnknownXMLObjects().isEmpty()) {
        descBuilder.extensions(roleExtensions);
      }

      descBuilder.keyDescriptors(this.buildKeyDescriptors());

      // NameID formats
      //
      final List<String> nameIdFormats = saml.getNameIdGeneratorFactory() != null
          ? saml.getNameIdGeneratorFactory().getSupportedFormats()
          : List.of(NameID.PERSISTENT, NameID.TRANSIENT);
      descBuilder.nameIDFormats(nameIdFormats);

      final List<SingleSignOnService> ssoServices = new ArrayList<>();
      ssoServices.add(SingleSignOnServiceBuilder.builder()
          .redirectBinding()
          .location(saml.getEndpointUrl(saml.getRedirectAuthnEndpoint()))
          .build());
      ssoServices.add(SingleSignOnServiceBuilder.builder()
          .postBinding()
          .location(saml.getEndpointUrl(saml.getPostAuthnEndpoint()))
          .build());

      // Optional Holder-of-key support
      //
      if (saml.getHokRedirectAuthnEndpoint() != null) {
        ssoServices.add(SingleSignOnServiceBuilder.builder()
            .hokRedirectBinding()
            .location(saml.getHokEndpointUrl(saml.getHokRedirectAuthnEndpoint()))
            .build());
      }
      if (saml.getHokPostAuthnEndpoint() != null) {
        ssoServices.add(SingleSignOnServiceBuilder.builder()
            .hokPostBinding()
            .location(saml.getHokEndpointUrl(saml.getHokPostAuthnEndpoint()))
            .build());
      }

      descBuilder.singleSignOnServices(ssoServices);

      // The builder adds role descriptors, so the template's descriptor is removed before the completed one is added.
      if (existingSsoDescriptor != null) {
        builder.object().getRoleDescriptors().remove(existingSsoDescriptor);
      }
      builder.ssoDescriptor(descBuilder.build());

      // Organization
      //
      if (this.organization != null) {
        final OrganizationBuilder b = OrganizationBuilder.builder();
        b.organizationNames(toLocalizedStrings(this.organization.names()));
        b.organizationDisplayNames(toLocalizedStrings(this.organization.displayNames()));
        b.organizationURLs(toLocalizedStrings(this.organization.urls()));

        if (StringUtils.hasText(this.organization.number())) {
          final OrganizationNumber number =
              (OrganizationNumber) XMLObjectSupport.buildXMLObject(OrganizationNumber.DEFAULT_ELEMENT_NAME);
          number.setValue(this.organization.number());

          final Extensions orgext = (Extensions) XMLObjectSupport.buildXMLObject(Extensions.DEFAULT_ELEMENT_NAME);
          orgext.getUnknownXMLObjects().add(number);

          b.object().setExtensions(orgext);
        }

        builder.organization(b.build());
      }

      // ContactPerson:s
      //
      if (this.contactPersons != null) {
        builder.contactPersons(this.contactPersons.entrySet().stream()
            .map(e -> toContactPerson(e.getKey(), e.getValue()))
            .toList());
      }

      return builder;
    }
    catch (final IOException | XMLParserException | UnmarshallingException e) {
      throw new IllegalArgumentException("Failed to construct IdP metadata - " + e.getMessage(), e);
    }
  }

  /**
   * Builds the {@code KeyDescriptor} elements.
   *
   * @return the key descriptors
   */
  private @Nonnull List<KeyDescriptor> buildKeyDescriptors() {
    final Saml2IdpConfigurer saml = this.samlConfigurer;
    final PkiCredential defaultCredential = saml.getDefaultCredential();

    final List<KeyDescriptor> keyDescriptors = new ArrayList<>();
    boolean signAssigned = false;
    boolean encryptAssigned = false;

    // The specific credentials, without falling back to the default credential.
    final PkiCredential signCredential = saml.getAssignedSignCredential();
    final PkiCredential encryptCredential = saml.getAssignedEncryptCredential();

    if (signCredential != null) {
      signAssigned = true;
      keyDescriptors.add(
          KeyDescriptorBuilder.builder()
              .use(UsageType.SIGNING)
              .certificate(signCredential.getCertificate())
              .keyName(signCredential.getName())
              .build());
    }
    if (saml.getFutureSignCertificate() != null) {
      keyDescriptors.add(
          KeyDescriptorBuilder.builder()
              .use(UsageType.SIGNING)
              .certificate(saml.getFutureSignCertificate())
              .build());
    }
    if (encryptCredential != null) {
      encryptAssigned = true;
      final KeyDescriptorBuilder kdBuilder = KeyDescriptorBuilder.builder()
          .use(UsageType.ENCRYPTION)
          .certificate(encryptCredential.getCertificate())
          .keyName(encryptCredential.getName());
      if (this.encryptionMethods != null) {
        kdBuilder.encryptionMethodsExt(this.buildEncryptionMethods());
      }
      keyDescriptors.add(kdBuilder.build());
    }
    if (defaultCredential != null && (!signAssigned || !encryptAssigned)) {
      final UsageType usage =
          signAssigned ? UsageType.ENCRYPTION : encryptAssigned ? UsageType.SIGNING : UsageType.UNSPECIFIED;

      final KeyDescriptorBuilder kdBuilder = KeyDescriptorBuilder.builder()
          .use(usage)
          .certificate(defaultCredential.getCertificate())
          .keyName(defaultCredential.getName());

      if ((usage == UsageType.ENCRYPTION || usage == UsageType.UNSPECIFIED) && this.encryptionMethods != null) {
        kdBuilder.encryptionMethodsExt(this.buildEncryptionMethods());
      }
      keyDescriptors.add(kdBuilder.build());
    }
    return keyDescriptors;
  }

  /**
   * Builds the {@code EncryptionMethod} elements.
   *
   * @return the encryption methods
   */
  private @Nonnull List<EncryptionMethod> buildEncryptionMethods() {
    return Objects.requireNonNull(this.encryptionMethods).stream()
        .filter(e -> StringUtils.hasText(e.algorithm()))
        .map(e -> {
          final EncryptionMethodBuilder builder = EncryptionMethodBuilder.builder()
              .algorithm(e.algorithm());
          if (e.oaepParams() != null) {
            builder.oAEPparams(e.oaepParams());
          }
          final EncryptionMethod em = builder.build();
          if (e.keySize() != null) {
            // EncryptionMethodBuilder.keySize does not assign the value, so the element is built here.
            final KeySize keySize = (KeySize) XMLObjectSupport.buildXMLObject(KeySize.DEFAULT_ELEMENT_NAME);
            keySize.setValue(e.keySize());
            em.setKeySize(keySize);
          }

          if (StringUtils.hasText(e.digestMethod())) {
            final org.opensaml.xmlsec.signature.DigestMethod dm =
                (org.opensaml.xmlsec.signature.DigestMethod) XMLObjectSupport.buildXMLObject(
                    org.opensaml.xmlsec.signature.DigestMethod.DEFAULT_ELEMENT_NAME);
            dm.setAlgorithm(e.digestMethod());
            em.getUnknownXMLObjects().add(dm);
          }
          return em;
        })
        .toList();
  }

  /**
   * Builds an {@link UIInfo} element.
   *
   * @return an {@link UIInfo} element or {@code null}
   */
  private @Nullable UIInfo buildUiInfo() {
    if (this.uiInfo == null) {
      return null;
    }
    final UIInfoBuilder uiBuilder = UIInfoBuilder.builder();
    uiBuilder.displayNames(toLocalizedStrings(this.uiInfo.displayNames()));
    uiBuilder.descriptions(toLocalizedStrings(this.uiInfo.descriptions()));
    uiBuilder.logos(Optional.ofNullable(this.uiInfo.logotypes())
        .map(l -> l.stream()
            .map(logo -> LogoBuilder.builder()
                .url(logo.path() != null
                    ? this.samlConfigurer.getServer().getBaseUrl() + logo.path()
                    : logo.url())
                .language(logo.languageTag())
                .height(logo.height())
                .width(logo.width())
                .build())
            .toList())
        .orElse(null));

    return uiBuilder.build();
  }

  /**
   * Turns a map of language tags and strings into localized strings.
   *
   * @param strings the strings, keyed by language tag
   * @return the localized strings, or {@code null}
   */
  private static @Nullable List<LocalizedString> toLocalizedStrings(final @Nullable Map<String, String> strings) {
    return Optional.ofNullable(strings)
        .map(n -> n.entrySet().stream()
            .map(e -> new LocalizedString(e.getValue(), e.getKey()))
            .toList())
        .orElse(null);
  }

  /**
   * Creates a {@link ContactPerson} element.
   *
   * @param type the type
   * @param contactPerson the contact person
   * @return a {@link ContactPerson}
   */
  private static @Nonnull ContactPerson toContactPerson(final @Nonnull ContactPersonType type,
      final @Nonnull IdpMetadataElements.ContactPerson contactPerson) {

    final ContactPerson cp = ContactPersonBuilder.builder()
        .type(toOpenSamlEnum(type))
        .company(contactPerson.company())
        .givenName(contactPerson.givenName())
        .surname(contactPerson.surname())
        .emailAddresses(contactPerson.emailAddresses())
        .telephoneNumbers(contactPerson.telephoneNumbers())
        .build();

    if (type == ContactPersonType.security) {
      cp.getUnknownAttributes().put(new QName("http://refeds.org/metadata", "contactType", "remd"),
          "http://refeds.org/metadata/contactType/security");
    }
    return cp;
  }

  /**
   * Maps a contact person type to its OpenSAML value.
   *
   * @param type the type
   * @return the OpenSAML value
   */
  private static @Nonnull ContactPersonTypeEnumeration toOpenSamlEnum(final @Nonnull ContactPersonType type) {
    if (type == ContactPersonType.security) {
      return ContactPersonTypeEnumeration.OTHER;
    }
    for (final ContactPersonTypeEnumeration e : ContactPersonTypeEnumeration.values()) {
      if (e.toString().equals(type.name())) {
        return e;
      }
    }
    throw new IllegalArgumentException("Unknown ContactPerson type: " + type.name());
  }

}
