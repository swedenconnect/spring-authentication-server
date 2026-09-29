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
package se.swedenconnect.spring.authnserver.saml.metadata;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.ext.saml2mdui.UIInfo;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;

import net.shibboleth.shared.resolver.ResolverException;
import se.swedenconnect.opensaml.saml2.metadata.build.EntityAttributesBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.EntityDescriptorBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.ExtensionsBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.LogoBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.OrganizationBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.SPSSODescriptorBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.UIInfoBuilder;
import se.swedenconnect.opensaml.common.utils.LocalizedString;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.registry.ClientRegistryException;
import se.swedenconnect.spring.authnserver.registry.DisplayName;
import se.swedenconnect.spring.authnserver.registry.Logo;
import se.swedenconnect.spring.authnserver.registry.RequesterRecord;
import se.swedenconnect.spring.authnserver.saml.attributes.OpenSamlTestBase;

/**
 * Tests for {@link SamlMetadataBackend}.
 *
 * @author Martin Lindström
 */
class SamlMetadataBackendTest extends OpenSamlTestBase {

  private static final String ENTITY_ID = "https://sp.example.com";

  private static final String LOA3_PNR = "http://id.elegnamnden.se/ec/1.0/loa3-pnr";

  private static final String MOBILE_AUTH = "http://id.elegnamnden.se/sprop/1.0/mobile-auth";

  @Test
  void theBackendAnswersForSaml() {
    final SamlMetadataBackend backend = new SamlMetadataBackend(mock(MetadataResolver.class));
    assertThat(backend.getProtocol()).isEqualTo(AuthenticationProtocol.SAML);
    assertThat(backend.getName()).isEqualTo(SamlMetadataBackend.DEFAULT_NAME);
    assertThat(new SamlMetadataBackend(mock(MetadataResolver.class), "other").getName()).isEqualTo("other");
  }

  @Test
  void displayNamesAndLogosComeFromTheUiInformation() {
    final EntityDescriptor metadata = EntityDescriptorBuilder.builder()
        .entityID(ENTITY_ID)
        .roleDescriptors(SPSSODescriptorBuilder.builder()
            .extensions(ExtensionsBuilder.builder()
                .extension(UIInfoBuilder.builder()
                    .displayNames(
                        new LocalizedString("Tjänsten", "sv"),
                        new LocalizedString("The Service", "en"))
                    .logos(
                        LogoBuilder.logo("https://sp.example.com/sv.svg", "sv", 40, 80),
                        LogoBuilder.logo("https://sp.example.com/logo.svg", 40, 80))
                    .build())
                .build())
            .build())
        .build();

    final RequesterRecord record = SamlMetadataBackend.toRecord(metadata);

    assertThat(record.requester().protocol()).isEqualTo(AuthenticationProtocol.SAML);
    assertThat(record.getIdentifier()).isEqualTo(ENTITY_ID);
    assertThat(record.displayNames()).containsExactlyInAnyOrder(
        new DisplayName("sv", "Tjänsten"), new DisplayName("en", "The Service"));
    assertThat(record.getDisplayName("sv")).isEqualTo("Tjänsten");
    assertThat(record.logos()).containsExactly(
        new Logo("sv", "https://sp.example.com/sv.svg", 40, 80),
        new Logo(null, "https://sp.example.com/logo.svg", 40, 80));
    assertThat(record.getProtocolMetadata(EntityDescriptor.class)).isSameAs(metadata);
    assertThat(record.marks()).isEmpty();
  }

  @Test
  void displayNamesFallBackToTheOrganisation() {
    final EntityDescriptor metadata = EntityDescriptorBuilder.builder()
        .entityID(ENTITY_ID)
        .roleDescriptors(SPSSODescriptorBuilder.builder()
            .extensions(ExtensionsBuilder.builder()
                .extension(UIInfoBuilder.builder()
                    .displayNames(new LocalizedString("Tjänsten", "sv"))
                    .build())
                .build())
            .build())
        .organization(OrganizationBuilder.builder()
            .organizationDisplayNames(
                new LocalizedString("Ignored, UIInfo wins", "sv"),
                new LocalizedString("The Organisation", "en"))
            .organizationNames(
                new LocalizedString("Ignored, display name wins", "en"),
                new LocalizedString("Die Organisation", "de"))
            .build())
        .build();

    final RequesterRecord record = SamlMetadataBackend.toRecord(metadata);

    assertThat(record.getDisplayName("sv")).isEqualTo("Tjänsten");
    assertThat(record.getDisplayName("en")).isEqualTo("The Organisation");
    assertThat(record.getDisplayName("de")).isEqualTo("Die Organisation");
    assertThat(record.logos()).isEmpty();
  }

  @Test
  void aDisplayNameWithoutALanguageIsKept() {
    final org.opensaml.saml.ext.saml2mdui.DisplayName displayName =
        (org.opensaml.saml.ext.saml2mdui.DisplayName) XMLObjectSupport.buildXMLObject(
            org.opensaml.saml.ext.saml2mdui.DisplayName.DEFAULT_ELEMENT_NAME);
    displayName.setValue("The Service");
    final UIInfo uiInfo = (UIInfo) XMLObjectSupport.buildXMLObject(UIInfo.DEFAULT_ELEMENT_NAME);
    uiInfo.getDisplayNames().add(displayName);

    final EntityDescriptor metadata = EntityDescriptorBuilder.builder()
        .entityID(ENTITY_ID)
        .roleDescriptors(SPSSODescriptorBuilder.builder()
            .extensions(ExtensionsBuilder.builder()
                .extension(uiInfo)
                .build())
            .build())
        .build();

    final RequesterRecord record = SamlMetadataBackend.toRecord(metadata);

    assertThat(record.displayNames()).containsExactly(new DisplayName(null, "The Service"));
    assertThat(record.getDisplayName("sv")).isEqualTo("The Service");
  }

  @Test
  void theMarksAreTheEntityCategories() {
    final EntityDescriptor metadata = EntityDescriptorBuilder.builder()
        .entityID(ENTITY_ID)
        .extensions(ExtensionsBuilder.builder()
            .extension(EntityAttributesBuilder.builder()
                .entityCategoriesAttribute(LOA3_PNR, MOBILE_AUTH)
                .build())
            .build())
        .roleDescriptors(SPSSODescriptorBuilder.builder().build())
        .build();

    final RequesterRecord record = SamlMetadataBackend.toRecord(metadata);

    assertThat(record.marks()).containsExactlyInAnyOrder(LOA3_PNR, MOBILE_AUTH);
    assertThat(record.hasMark(LOA3_PNR)).isTrue();
    assertThat(record.hasMark("http://id.elegnamnden.se/ec/1.0/loa2-pnr")).isFalse();
  }

  @Test
  void aServiceProviderThatIsNotInTheMetadataIsNotKnown() throws Exception {
    final MetadataResolver resolver = mock(MetadataResolver.class);
    when(resolver.resolveSingle(any())).thenReturn(null);

    assertThat(new SamlMetadataBackend(resolver).lookup(ENTITY_ID)).isNull();
  }

  @Test
  void aMetadataSourceThatFailsIsNotAnUnknownServiceProvider() throws Exception {
    final MetadataResolver resolver = mock(MetadataResolver.class);
    when(resolver.resolveSingle(any())).thenThrow(new ResolverException("metadata could not be read"));

    assertThatThrownBy(() -> new SamlMetadataBackend(resolver).lookup(ENTITY_ID))
        .isInstanceOf(ClientRegistryException.class)
        .hasMessageContaining("metadata could not be read");
  }

  @Test
  void askingForAMarkFindsNothingForSaml() throws Exception {
    final EntityDescriptor metadata = EntityDescriptorBuilder.builder()
        .entityID(ENTITY_ID)
        .roleDescriptors(SPSSODescriptorBuilder.builder().build())
        .build();
    final MetadataResolver resolver = mock(MetadataResolver.class);
    when(resolver.resolveSingle(any())).thenReturn(metadata);

    final RequesterRecord record = new SamlMetadataBackend(resolver).requestMark(ENTITY_ID, LOA3_PNR);

    assertThat(record).isNotNull();
    assertThat(record.marks()).isEmpty();
  }

  @Test
  void aLogoWithoutAUrlIsLeftOut() {
    final EntityDescriptor metadata = EntityDescriptorBuilder.builder()
        .entityID(ENTITY_ID)
        .roleDescriptors(SPSSODescriptorBuilder.builder()
            .extensions(ExtensionsBuilder.builder()
                .extension(UIInfoBuilder.builder()
                    .logos(List.of(LogoBuilder.builder().height(40).width(80).build()))
                    .build())
                .build())
            .build())
        .build();

    assertThat(SamlMetadataBackend.toRecord(metadata).logos()).isEmpty();
  }

}
