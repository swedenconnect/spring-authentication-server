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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.mockito.Mockito.mock;

import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import javax.xml.namespace.QName;

import net.shibboleth.shared.xml.SerializeSupport;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.opensaml.saml.ext.saml2alg.DigestMethod;
import org.opensaml.saml.ext.saml2alg.SigningMethod;
import org.opensaml.saml.ext.saml2mdattr.EntityAttributes;
import org.opensaml.saml.ext.saml2mdui.UIInfo;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.metadata.ContactPerson;
import org.opensaml.saml.saml2.metadata.ContactPersonTypeEnumeration;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;

import se.swedenconnect.opensaml.saml2.attribute.AttributeUtils;
import se.swedenconnect.opensaml.saml2.metadata.EntityDescriptorContainer;
import se.swedenconnect.opensaml.saml2.metadata.EntityDescriptorUtils;
import se.swedenconnect.opensaml.sweid.saml2.authn.psc.RequestedPrincipalSelection;
import se.swedenconnect.opensaml.sweid.saml2.metadata.entitycategory.EntityCategoryConstants;
import se.swedenconnect.opensaml.sweid.saml2.metadata.ext.OrganizationNumber;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.spring.authnserver.authentication.provider.AbstractUserAuthenticationProvider;
import se.swedenconnect.spring.authnserver.authentication.provider.UserAuthenticationInputToken;
import se.swedenconnect.spring.authnserver.config.AuthnServerConfigurer;
import se.swedenconnect.spring.authnserver.entity.EntityInformation;
import se.swedenconnect.spring.authnserver.saml.attributes.OpenSamlTestBase;
import se.swedenconnect.spring.authnserver.saml.nameid.DefaultNameIDGeneratorFactory;

/**
 * Test cases for the IdP metadata built by {@link Saml2IdpMetadataEndpointConfigurer}.
 *
 * @author Martin Lindström
 */
class Saml2IdpMetadataEndpointConfigurerTest extends OpenSamlTestBase {

  private static final String BASE_URL = "https://idp.example.com/auth";

  private static final String LOA3 = "http://id.elegnamnden.se/loa/1.0/loa3";

  private static final String LOA4 = "http://id.elegnamnden.se/loa/1.0/loa4";

  private static final String ASSURANCE_CERTIFICATION = "urn:oasis:names:tc:SAML:attribute:assurance-certification";

  private static final String ENTITY_CATEGORY = "http://macedir.org/entity-category";

  /** A provider declaring authentication contexts and entity categories. */
  static class TestProvider extends AbstractUserAuthenticationProvider {

    private final List<String> authnContexts;

    private final List<String> entityCategories;

    TestProvider(final List<String> authnContexts, final List<String> entityCategories) {
      this.authnContexts = authnContexts;
      this.entityCategories = entityCategories;
    }

    @Override
    public @NonNull String getName() {
      return "test";
    }

    @Override
    public @NonNull List<String> getSupportedAuthnContextUris() {
      return this.authnContexts;
    }

    @Override
    public @NonNull List<String> getEntityCategories() {
      return this.entityCategories;
    }

    @Override
    protected @NonNull Authentication authenticate(final @NonNull UserAuthenticationInputToken token,
        final @NonNull List<String> authnContextUris) {
      throw new UnsupportedOperationException();
    }
  }

  @Test
  void theDefaultMetadataHoldsTheValuesOfTheConfigurers() {
    final EntityDescriptorContainer container = container(new AuthnServerConfigurer().baseUrl(BASE_URL),
        new Saml2IdpConfigurer().defaultCredential(TestCredentials.SIGN), m -> {});
    final EntityDescriptor ed = container.getDescriptor();

    assertThat(ed.getEntityID()).isEqualTo(BASE_URL);
    assertThat(ed.getCacheDuration()).isEqualTo(Duration.ofHours(24));

    final IDPSSODescriptor idp = ed.getIDPSSODescriptor(SAMLConstants.SAML20P_NS);
    assertThat(idp.getWantAuthnRequestsSigned()).isTrue();
    assertThat(idp.getNameIDFormats()).extracting(f -> f.getURI())
        .containsExactly(NameID.PERSISTENT, NameID.TRANSIENT);
    assertThat(idp.getSingleSignOnServices())
        .extracting(SingleSignOnService::getBinding, SingleSignOnService::getLocation)
        .containsExactly(
            org.assertj.core.groups.Tuple.tuple(SAMLConstants.SAML2_REDIRECT_BINDING_URI,
                BASE_URL + "/saml2/redirect/authn"),
            org.assertj.core.groups.Tuple.tuple(SAMLConstants.SAML2_POST_BINDING_URI, BASE_URL + "/saml2/post/authn"));

    // Only the default credential, for all uses.
    assertThat(idp.getKeyDescriptors()).hasSize(1);
    assertThat(idp.getKeyDescriptors().getFirst().getUse()).isEqualTo(UsageType.UNSPECIFIED);

    // No UIInfo, no organization and no contacts.
    assertThat(idp.getExtensions()).isNull();
    assertThat(ed.getOrganization()).isNull();
    assertThat(ed.getContactPersons()).isEmpty();
  }

  @Test
  void theMetadataIsSignedWithTheDefaultCredentialAndIsValidForTheValidityPeriod() throws Exception {
    final EntityDescriptorContainer container = container(new AuthnServerConfigurer().baseUrl(BASE_URL),
        new Saml2IdpConfigurer().defaultCredential(TestCredentials.SIGN),
        m -> m.validityPeriod(Duration.ofDays(2)).cacheDuration(Duration.ofHours(1)));
    container.update(true);
    final EntityDescriptor ed = container.getDescriptor();

    assertThat(ed.getCacheDuration()).isEqualTo(Duration.ofHours(1));
    assertThat(ed.getValidUntil()).isBetween(Instant.now().plus(Duration.ofDays(2)).minusSeconds(60),
        Instant.now().plus(Duration.ofDays(2)).plusSeconds(60));
    assertSignedBy(ed, TestCredentials.SIGN);
  }

  @Test
  void theMetadataSigningCredentialWinsOverTheDefaultCredential() throws Exception {
    final EntityDescriptorContainer container = container(new AuthnServerConfigurer().baseUrl(BASE_URL),
        new Saml2IdpConfigurer().defaultCredential(TestCredentials.SIGN)
            .metadataSignCredential(TestCredentials.METADATA), m -> {});
    container.update(true);
    assertSignedBy(container.getDescriptor(), TestCredentials.METADATA);
  }

  @Test
  void withoutMetadataSigningOrDefaultCredentialTheMetadataIsNotSigned() throws Exception {
    final EntityDescriptorContainer container = container(new AuthnServerConfigurer().baseUrl(BASE_URL),
        new Saml2IdpConfigurer().signCredential(TestCredentials.SIGN).encryptCredential(TestCredentials.ENCRYPT),
        m -> {});
    container.update(false);
    assertThat(container.getDescriptor().getSignature()).isNull();
  }

  @Test
  void theSpecificCredentialsArePublishedForTheirUse() throws Exception {
    final X509Certificate future = TestCredentials.METADATA.getCertificate();
    final EntityDescriptor ed = descriptor(new AuthnServerConfigurer().baseUrl(BASE_URL),
        new Saml2IdpConfigurer()
            .defaultCredential(TestCredentials.METADATA)
            .signCredential(TestCredentials.SIGN)
            .encryptCredential(TestCredentials.ENCRYPT)
            .futureSignCertificate(future),
        m -> m.encryptionMethods(List.of(new IdpMetadataElements.EncryptionMethod(
            "http://www.w3.org/2009/xmlenc11#rsa-oaep", null, null, "http://www.w3.org/2001/04/xmlenc#sha256"))));

    final List<KeyDescriptor> kds = ed.getIDPSSODescriptor(SAMLConstants.SAML20P_NS).getKeyDescriptors();
    assertThat(kds).extracting(KeyDescriptor::getUse)
        .containsExactly(UsageType.SIGNING, UsageType.SIGNING, UsageType.ENCRYPTION);
    assertThat(kds.get(0).getKeyInfo().getKeyNames().getFirst().getValue()).isEqualTo("sign");
    assertThat(kds.get(2).getKeyInfo().getKeyNames().getFirst().getValue()).isEqualTo("encrypt");
    assertThat(kds.get(2).getEncryptionMethods()).hasSize(1);
    assertThat(kds.get(2).getEncryptionMethods().getFirst().getAlgorithm())
        .isEqualTo("http://www.w3.org/2009/xmlenc11#rsa-oaep");
    assertThat(kds.get(2).getEncryptionMethods().getFirst().getUnknownXMLObjects()).hasSize(1);
  }

  @Test
  void theDefaultCredentialIsPublishedForTheUseThatHasNoSpecificCredential() throws Exception {
    final EntityDescriptor ed = descriptor(new AuthnServerConfigurer().baseUrl(BASE_URL),
        new Saml2IdpConfigurer().defaultCredential(TestCredentials.ENCRYPT).signCredential(TestCredentials.SIGN),
        m -> m.encryptionMethods(List.of(
            new IdpMetadataElements.EncryptionMethod("http://www.w3.org/2009/xmlenc11#aes256-gcm", 256, null, null))));

    final List<KeyDescriptor> kds = ed.getIDPSSODescriptor(SAMLConstants.SAML20P_NS).getKeyDescriptors();
    assertThat(kds).extracting(KeyDescriptor::getUse).containsExactly(UsageType.SIGNING, UsageType.ENCRYPTION);
    assertThat(kds.get(1).getEncryptionMethods()).hasSize(1);
    assertThat(kds.get(1).getEncryptionMethods().getFirst().getKeySize().getValue()).isEqualTo(256);
  }

  @Test
  void theAuthnContextsAndEntityCategoriesOfTheProvidersArePublished() throws Exception {
    final AuthnServerConfigurer server = new AuthnServerConfigurer().baseUrl(BASE_URL)
        .supportsUserMessage(true)
        .authenticationProvider(new TestProvider(List.of(LOA3), List.of("http://id.elegnamnden.se/ec/1.0/loa3-pnr")))
        .authenticationProvider(new TestProvider(List.of(LOA3, LOA4), List.of()));
    final EntityDescriptor ed =
        descriptor(server, new Saml2IdpConfigurer().defaultCredential(TestCredentials.SIGN), m -> {});

    final EntityAttributes attributes =
        EntityDescriptorUtils.getMetadataExtension(ed.getExtensions(), EntityAttributes.class);
    assertThat(attributeValues(attributes, ASSURANCE_CERTIFICATION)).containsExactly(LOA3, LOA4);
    assertThat(attributeValues(attributes, ENTITY_CATEGORY)).containsExactly(
        "http://id.elegnamnden.se/ec/1.0/loa3-pnr",
        EntityCategoryConstants.GENERAL_CATEGORY_SUPPORTS_USER_MESSAGE.getUri());
  }

  @Test
  void theUserMessageCategoryFollowsTheSamlSetting() throws Exception {
    final AuthnServerConfigurer server = new AuthnServerConfigurer().baseUrl(BASE_URL)
        .supportsUserMessage(true)
        .authenticationProvider(new TestProvider(List.of(LOA3), List.of("http://id.elegnamnden.se/ec/1.0/loa3-pnr")));
    final EntityDescriptor ed = descriptor(server,
        new Saml2IdpConfigurer().defaultCredential(TestCredentials.SIGN).supportsUserMessage(false), m -> {});

    final EntityAttributes attributes =
        EntityDescriptorUtils.getMetadataExtension(ed.getExtensions(), EntityAttributes.class);
    assertThat(attributeValues(attributes, ENTITY_CATEGORY)).containsExactly(
        "http://id.elegnamnden.se/ec/1.0/loa3-pnr");
  }

  @Test
  void withoutEntityCategoriesTheUserMessageCategoryIsNotPublished() throws Exception {
    final AuthnServerConfigurer server = new AuthnServerConfigurer().baseUrl(BASE_URL)
        .supportsUserMessage(true)
        .authenticationProvider(new TestProvider(List.of(LOA3), List.of()));
    final EntityDescriptor ed =
        descriptor(server, new Saml2IdpConfigurer().defaultCredential(TestCredentials.SIGN), m -> {});

    final EntityAttributes attributes =
        EntityDescriptorUtils.getMetadataExtension(ed.getExtensions(), EntityAttributes.class);
    assertThat(attributeValues(attributes, ENTITY_CATEGORY)).isEmpty();
  }

  @Test
  void theUiInfoOrganizationAndContactsArePublished() throws Exception {
    final Map<EntityInformation.ContactPersonType, EntityInformation.ContactPerson> contacts =
        new LinkedHashMap<>();
    contacts.put(EntityInformation.ContactPersonType.technical,
        new EntityInformation.ContactPerson("Company", "Kalle", "Kula", List.of("kalle@example.com"), null));
    contacts.put(EntityInformation.ContactPersonType.security,
        new EntityInformation.ContactPerson(null, null, null, List.of("security@example.com"), null));

    final EntityDescriptor ed = descriptor(new AuthnServerConfigurer().baseUrl(BASE_URL),
        new Saml2IdpConfigurer().defaultCredential(TestCredentials.SIGN),
        m -> m
            .uiInfo(new EntityInformation.UiInfo(Map.of("en", "Test IdP"), Map.of("sv", "Test-IdP"), List.of(
                new EntityInformation.Logo(null, "/images/logo.svg", 100, 100, null),
                new EntityInformation.Logo("https://cdn.example.com/logo.png", null, 50, 50, "en"))))
            .organization(new EntityInformation.Organization(Map.of("en", "Org"), Map.of("en", "The Org"),
                Map.of("en", "https://www.example.com"), "556677-8899"))
            .contactPersons(contacts)
            .requestedPrincipalSelection(List.of("urn:oid:1.2.752.29.4.13")));

    final IDPSSODescriptor idp = ed.getIDPSSODescriptor(SAMLConstants.SAML20P_NS);
    final UIInfo uiInfo = EntityDescriptorUtils.getMetadataExtension(idp.getExtensions(), UIInfo.class);
    assertThat(uiInfo.getDisplayNames().getFirst().getValue()).isEqualTo("Test IdP");
    assertThat(uiInfo.getDescriptions().getFirst().getXMLLang()).isEqualTo("sv");
    assertThat(uiInfo.getLogos()).extracting(l -> l.getURI())
        .containsExactly(BASE_URL + "/images/logo.svg", "https://cdn.example.com/logo.png");

    final RequestedPrincipalSelection rps =
        EntityDescriptorUtils.getMetadataExtension(idp.getExtensions(), RequestedPrincipalSelection.class);
    assertThat(rps.getMatchValues()).extracting(v -> v.getName()).containsExactly("urn:oid:1.2.752.29.4.13");

    assertThat(ed.getOrganization().getOrganizationNames().getFirst().getValue()).isEqualTo("Org");
    assertThat(ed.getOrganization().getDisplayNames().getFirst().getValue()).isEqualTo("The Org");
    assertThat(ed.getOrganization().getURLs().getFirst().getURI()).isEqualTo("https://www.example.com");
    assertThat(EntityDescriptorUtils.getMetadataExtension(ed.getOrganization().getExtensions(),
        OrganizationNumber.class).getValue()).isEqualTo("556677-8899");

    final List<ContactPerson> cps = ed.getContactPersons();
    assertThat(cps).extracting(ContactPerson::getType)
        .containsExactly(ContactPersonTypeEnumeration.TECHNICAL, ContactPersonTypeEnumeration.OTHER);
    assertThat(cps.get(0).getGivenName().getValue()).isEqualTo("Kalle");
    assertThat(cps.get(1).getUnknownAttributes().get(new QName("http://refeds.org/metadata", "contactType")))
        .isEqualTo("http://refeds.org/metadata/contactType/security");
  }

  @Test
  void sharedEntityInformationGivesTheSameMetadataAsTheSamlValues() throws Exception {
    final EntityInformation information = sampleInformation();

    final EntityDescriptor fromSaml = descriptor(new AuthnServerConfigurer().baseUrl(BASE_URL),
        new Saml2IdpConfigurer().defaultCredential(TestCredentials.SIGN),
        m -> m.uiInfo(information.uiInfo()).organization(information.organization())
            .contactPersons(information.contactPersons()));
    final EntityDescriptor fromShared = descriptor(
        new AuthnServerConfigurer().baseUrl(BASE_URL).entityInformation(information),
        new Saml2IdpConfigurer().defaultCredential(TestCredentials.SIGN), m -> {});

    assertThat(xml(uiInfo(fromShared))).isEqualTo(xml(uiInfo(fromSaml)));
    assertThat(xml(fromShared.getOrganization())).isEqualTo(xml(fromSaml.getOrganization()));
    assertThat(fromShared.getContactPersons().stream().map(Saml2IdpMetadataEndpointConfigurerTest::xml).toList())
        .isEqualTo(fromSaml.getContactPersons().stream().map(Saml2IdpMetadataEndpointConfigurerTest::xml).toList());
  }

  @Test
  void theSamlValuesOverrideTheSharedEntityInformation() throws Exception {
    final Map<EntityInformation.ContactPersonType, EntityInformation.ContactPerson> contacts =
        new LinkedHashMap<>();
    contacts.put(EntityInformation.ContactPersonType.support,
        new EntityInformation.ContactPerson(null, "Saml", null, List.of("saml-support@example.com"), null));

    final EntityDescriptor ed = descriptor(
        new AuthnServerConfigurer().baseUrl(BASE_URL).entityInformation(sampleInformation()),
        new Saml2IdpConfigurer().defaultCredential(TestCredentials.SIGN),
        m -> m.uiInfo(new EntityInformation.UiInfo(Map.of("en", "SAML IdP"), null, null))
            .organization(new EntityInformation.Organization(null, null, null, "5569876543"))
            .contactPersons(contacts));

    final UIInfo uiInfo = uiInfo(ed);
    assertThat(uiInfo.getDisplayNames()).extracting(n -> n.getValue()).containsExactly("SAML IdP");
    assertThat(uiInfo.getDescriptions()).extracting(n -> n.getValue()).containsExactly("Delad");
    assertThat(uiInfo.getLogos()).hasSize(1);
    assertThat(ed.getOrganization().getOrganizationNames().getFirst().getValue()).isEqualTo("Shared Org");
    assertThat(EntityDescriptorUtils.getMetadataExtension(ed.getOrganization().getExtensions(),
        OrganizationNumber.class).getValue()).isEqualTo("5569876543");
    assertThat(ed.getContactPersons()).extracting(ContactPerson::getType)
        .containsExactly(ContactPersonTypeEnumeration.TECHNICAL, ContactPersonTypeEnumeration.SUPPORT);
    assertThat(ed.getContactPersons().get(1).getGivenName().getValue()).isEqualTo("Saml");
  }

  @Test
  void anInvalidSharedLogoIsRejected() {
    final EntityInformation information = new EntityInformation(new EntityInformation.UiInfo(null, null,
        List.of(new EntityInformation.Logo(null, null, 10, 10, null))), null, null);
    assertThatIllegalArgumentException().isThrownBy(() -> descriptor(
        new AuthnServerConfigurer().baseUrl(BASE_URL).entityInformation(information),
        new Saml2IdpConfigurer().defaultCredential(TestCredentials.SIGN), m -> {}));
  }

  @Test
  void theAlgorithmsArePlacedUnderTheEntityDescriptorOrTheRole() throws Exception {
    final List<IdpMetadataElements.SigningMethod> signingMethods = List.of(
        new IdpMetadataElements.SigningMethod("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", 2048, null));
    final List<String> digestMethods = List.of("http://www.w3.org/2001/04/xmlenc#sha256");

    EntityDescriptor ed = descriptor(new AuthnServerConfigurer().baseUrl(BASE_URL),
        new Saml2IdpConfigurer().defaultCredential(TestCredentials.SIGN),
        m -> m.signingMethods(signingMethods).digestMethods(digestMethods));
    assertThat(EntityDescriptorUtils.getMetadataExtensions(ed.getExtensions(), DigestMethod.class)).hasSize(1);
    assertThat(EntityDescriptorUtils.getMetadataExtensions(ed.getExtensions(), SigningMethod.class)).hasSize(1);
    assertThat(ed.getIDPSSODescriptor(SAMLConstants.SAML20P_NS).getExtensions()).isNull();

    ed = descriptor(new AuthnServerConfigurer().baseUrl(BASE_URL),
        new Saml2IdpConfigurer().defaultCredential(TestCredentials.SIGN),
        m -> m.signingMethods(signingMethods).signingMethodsUnderRole(true)
            .digestMethods(digestMethods).digestMethodsUnderRole(true));
    assertThat(EntityDescriptorUtils.getMetadataExtensions(ed.getExtensions(), DigestMethod.class)).isEmpty();
    assertThat(EntityDescriptorUtils.getMetadataExtensions(ed.getExtensions(), SigningMethod.class)).isEmpty();
    final IDPSSODescriptor idp = ed.getIDPSSODescriptor(SAMLConstants.SAML20P_NS);
    assertThat(EntityDescriptorUtils.getMetadataExtensions(idp.getExtensions(), DigestMethod.class)).hasSize(1);
    assertThat(EntityDescriptorUtils.getMetadataExtensions(idp.getExtensions(), SigningMethod.class)).hasSize(1);
  }

  @Test
  void theEndpointsFollowTheSamlPathAndTheHolderOfKeyBaseUrl() throws Exception {
    EntityDescriptor ed = descriptor(new AuthnServerConfigurer().baseUrl(BASE_URL),
        new Saml2IdpConfigurer().defaultCredential(TestCredentials.SIGN)
            .path("/idp")
            .redirectAuthnEndpoint("/sso/redirect")
            .hokRedirectAuthnEndpoint("/hok/redirect")
            .hokPostAuthnEndpoint("/hok/post")
            .hokBaseUrl("https://hok.example.com:8443/auth"),
        m -> {});
    assertThat(ed.getIDPSSODescriptor(SAMLConstants.SAML20P_NS).getSingleSignOnServices())
        .extracting(SingleSignOnService::getLocation)
        .containsExactly(
            BASE_URL + "/idp/sso/redirect",
            BASE_URL + "/idp/post/authn",
            "https://hok.example.com:8443/auth/idp/hok/redirect",
            "https://hok.example.com:8443/auth/idp/hok/post");

    ed = descriptor(new AuthnServerConfigurer().baseUrl(BASE_URL),
        new Saml2IdpConfigurer().defaultCredential(TestCredentials.SIGN).hokPostAuthnEndpoint("/hok/post"),
        m -> {});
    assertThat(ed.getIDPSSODescriptor(SAMLConstants.SAML20P_NS).getSingleSignOnServices())
        .extracting(SingleSignOnService::getLocation)
        .contains(BASE_URL + "/saml2/hok/post");
  }

  @Test
  void theEntityIdAndOtherValuesMayBeAssigned() throws Exception {
    final DefaultNameIDGeneratorFactory nameIdFactory = new DefaultNameIDGeneratorFactory("https://saml.example.com");
    nameIdFactory.setDefaultFormat(NameID.TRANSIENT);

    final EntityDescriptor ed = descriptor(new AuthnServerConfigurer().baseUrl(BASE_URL),
        new Saml2IdpConfigurer().defaultCredential(TestCredentials.SIGN)
            .entityId("https://saml.example.com")
            .requiresSignedRequests(false)
            .nameIdGeneratorFactory(nameIdFactory),
        m -> m.entityDescriptorCustomizer(e -> e.setID("_customized")));

    assertThat(ed.getEntityID()).isEqualTo("https://saml.example.com");
    assertThat(ed.getID()).isEqualTo("_customized");
    final IDPSSODescriptor idp = ed.getIDPSSODescriptor(SAMLConstants.SAML20P_NS);
    assertThat(idp.getWantAuthnRequestsSigned()).isFalse();
    assertThat(idp.getNameIDFormats()).extracting(f -> f.getURI())
        .containsExactly(NameID.TRANSIENT, NameID.PERSISTENT);
  }

  @Test
  void aTemplateIsCompletedWithTheConfiguredValues() throws Exception {
    final EntityDescriptor ed = descriptor(new AuthnServerConfigurer().baseUrl(BASE_URL),
        new Saml2IdpConfigurer().defaultCredential(TestCredentials.SIGN),
        m -> m.template(new ClassPathResource("metadata/idp-template.xml"))
            .uiInfo(new EntityInformation.UiInfo(Map.of("en", "Configured IdP"), null, null)));

    assertThat(ed.getEntityID()).isEqualTo(BASE_URL);
    assertThat(ed.getOrganization().getOrganizationNames().getFirst().getValue()).isEqualTo("Template Org");
    final IDPSSODescriptor idp = ed.getIDPSSODescriptor(SAMLConstants.SAML20P_NS);
    final List<UIInfo> uiInfos = EntityDescriptorUtils.getMetadataExtensions(idp.getExtensions(), UIInfo.class);
    assertThat(uiInfos).hasSize(1);
    assertThat(uiInfos.getFirst().getDisplayNames().getFirst().getValue()).isEqualTo("Configured IdP");
    assertThat(idp.getSingleSignOnServices()).extracting(SingleSignOnService::getLocation)
        .containsExactly(BASE_URL + "/saml2/redirect/authn", BASE_URL + "/saml2/post/authn");
  }

  @Test
  void aMissingOrInvalidValueIsRejected() {
    assertThatIllegalArgumentException().isThrownBy(() -> init(new Saml2IdpConfigurer()))
        .withMessageContaining("Missing SAML signing credential");
    assertThatIllegalArgumentException()
        .isThrownBy(() -> init(new Saml2IdpConfigurer().signCredential(TestCredentials.SIGN)))
        .withMessageContaining("Missing SAML encryption credential");
    assertThatNoException().isThrownBy(() -> init(
        new Saml2IdpConfigurer().signCredential(TestCredentials.SIGN).encryptCredential(TestCredentials.ENCRYPT)));

    assertThatIllegalArgumentException().isThrownBy(() -> init(
        new Saml2IdpConfigurer().defaultCredential(TestCredentials.SIGN).entityId(" ")));
    assertThatIllegalArgumentException().isThrownBy(() -> init(
        new Saml2IdpConfigurer().defaultCredential(TestCredentials.SIGN).hokBaseUrl("https://hok.example.com/")));
    assertThatIllegalArgumentException().isThrownBy(() -> init(
        new Saml2IdpConfigurer().defaultCredential(TestCredentials.SIGN).metadataEndpoint("metadata")));
    assertThatIllegalArgumentException().isThrownBy(() -> init(
        new Saml2IdpConfigurer().defaultCredential(TestCredentials.SIGN).hokPostAuthnEndpoint("hok")));
    assertThatIllegalArgumentException().isThrownBy(() -> init(
        new Saml2IdpConfigurer().defaultCredential(TestCredentials.SIGN).idpMetadataEndpoint(
            m -> m.uiInfo(new EntityInformation.UiInfo(null, null,
                List.of(new EntityInformation.Logo("https://a", "/b", null, null, null)))))));
    assertThatIllegalArgumentException().isThrownBy(() -> init(
        new Saml2IdpConfigurer().defaultCredential(TestCredentials.SIGN).idpMetadataEndpoint(
            m -> m.validityPeriod(Duration.ZERO))));
  }

  @Test
  void theCredentialsFallBackToTheDefaultCredential() {
    final Saml2IdpConfigurer saml = new Saml2IdpConfigurer().defaultCredential(TestCredentials.SIGN);
    assertThat(saml.getSignCredential()).isSameAs(TestCredentials.SIGN);
    assertThat(saml.getEncryptCredential()).isSameAs(TestCredentials.SIGN);
    assertThat(saml.getMetadataSignCredential()).isSameAs(TestCredentials.SIGN);

    saml.signCredential(TestCredentials.ENCRYPT).encryptCredential(TestCredentials.METADATA)
        .metadataSignCredential(TestCredentials.ENCRYPT);
    assertThat(saml.getSignCredential()).isSameAs(TestCredentials.ENCRYPT);
    assertThat(saml.getEncryptCredential()).isSameAs(TestCredentials.METADATA);
    assertThat(saml.getMetadataSignCredential()).isSameAs(TestCredentials.ENCRYPT);
  }

  private static void init(final Saml2IdpConfigurer saml) {
    new AuthnServerConfigurer().baseUrl(BASE_URL).protocol(saml.metadataResolver(mock(MetadataResolver.class)))
        .init(mock(HttpSecurity.class));
  }

  private static EntityDescriptor descriptor(final AuthnServerConfigurer server, final Saml2IdpConfigurer saml,
      final Consumer<Saml2IdpMetadataEndpointConfigurer> customizer) throws Exception {
    final EntityDescriptorContainer container = container(server, saml, customizer);
    return container.getDescriptor();
  }

  private static EntityDescriptorContainer container(final AuthnServerConfigurer server,
      final Saml2IdpConfigurer saml, final Consumer<Saml2IdpMetadataEndpointConfigurer> customizer) {
    final Saml2IdpMetadataEndpointConfigurer[] metadata = new Saml2IdpMetadataEndpointConfigurer[1];
    saml.idpMetadataEndpoint(m -> {
      customizer.accept(m);
      metadata[0] = m;
    });
    server.protocol(saml.metadataResolver(mock(MetadataResolver.class))).init(mock(HttpSecurity.class));
    return metadata[0].createEntityDescriptorContainer();
  }

  private static EntityInformation sampleInformation() {
    final Map<EntityInformation.ContactPersonType, EntityInformation.ContactPerson> contacts =
        new LinkedHashMap<>();
    contacts.put(EntityInformation.ContactPersonType.technical,
        new EntityInformation.ContactPerson("Company", "Kalle", "Kula", List.of("kalle@example.com"), null));
    contacts.put(EntityInformation.ContactPersonType.support,
        new EntityInformation.ContactPerson(null, null, null, List.of("support@example.com"), List.of("+4611")));
    return new EntityInformation(
        new EntityInformation.UiInfo(Map.of("sv", "Delad IdP"), Map.of("sv", "Delad"),
            List.of(new EntityInformation.Logo(null, "/images/logo.svg", 100, 100, null))),
        new EntityInformation.Organization(Map.of("en", "Shared Org"), Map.of("en", "Shared"),
            Map.of("en", "https://www.example.com"), "5561234567"),
        contacts);
  }

  private static UIInfo uiInfo(final EntityDescriptor ed) {
    return EntityDescriptorUtils.getMetadataExtension(
        ed.getIDPSSODescriptor(SAMLConstants.SAML20P_NS).getExtensions(), UIInfo.class);
  }

  private static String xml(final XMLObject object) {
    try {
      return SerializeSupport.nodeToString(XMLObjectSupport.marshall(object));
    }
    catch (final Exception e) {
      throw new IllegalStateException(e);
    }
  }

  private static List<String> attributeValues(final EntityAttributes attributes, final String name) {
    return attributes.getAttributes().stream()
        .filter(a -> name.equals(a.getName()))
        .map(Attribute.class::cast)
        .flatMap(a -> AttributeUtils.getAttributeStringValues(a).stream())
        .toList();
  }

  private static void assertSignedBy(final EntityDescriptor ed, final PkiCredential credential) throws Exception {
    assertThat(ed.getSignature()).isNotNull();
    SignatureValidator.validate(ed.getSignature(), new BasicX509Credential(credential.getCertificate()));
  }

}
