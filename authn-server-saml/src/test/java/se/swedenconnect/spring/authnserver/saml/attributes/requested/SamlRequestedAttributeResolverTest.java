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
package se.swedenconnect.spring.authnserver.saml.attributes.requested;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;

import se.swedenconnect.opensaml.eidas.ext.RequestedAttributes;
import se.swedenconnect.opensaml.saml2.metadata.build.AttributeConsumingServiceBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.EntityAttributesBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.EntityDescriptorBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.ExtensionsBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.SPSSODescriptorBuilder;
import se.swedenconnect.opensaml.sweid.saml2.attribute.AttributeConstants;
import se.swedenconnect.opensaml.sweid.saml2.authn.psc.build.MatchValueBuilder;
import se.swedenconnect.opensaml.sweid.saml2.authn.psc.build.PrincipalSelectionBuilder;
import se.swedenconnect.opensaml.sweid.saml2.metadata.entitycategory.EntityCategoryConstants;
import se.swedenconnect.spring.authnserver.attributes.AttributeIdentifiers;
import se.swedenconnect.spring.authnserver.attributes.GenericRequestedAttribute;
import se.swedenconnect.spring.authnserver.saml.attributes.SamlAttributeMapping;
import se.swedenconnect.spring.authnserver.saml.attributes.eidas.EidasAttributeMapping;
import se.swedenconnect.spring.authnserver.saml.attributes.eidas.EidasNaturalPersonAttributes;

/**
 * Tests for {@link SamlRequestedAttributeResolver}.
 *
 * @author Martin Lindström
 */
class SamlRequestedAttributeResolverTest extends RequestedAttributeTestSupport {

  private static final String LOA3_PNR = EntityCategoryConstants.SERVICE_ENTITY_CATEGORY_LOA3_PNR.getUri();

  private final SamlRequestedAttributeResolver resolver = new SamlRequestedAttributeResolver(List.of(LOA3_PNR));

  private static GenericRequestedAttribute attribute(final List<GenericRequestedAttribute> attributes,
      final String identifier) {
    return attributes.stream().filter(a -> a.getIdentifier().equals(identifier)).findFirst().orElse(null);
  }

  @Test
  void aRequestThatAsksForNothingGivesNothing() {
    final EntityDescriptor metadata = EntityDescriptorBuilder.builder()
        .entityID(SP_ENTITY_ID)
        .roleDescriptors(SPSSODescriptorBuilder.builder().build())
        .build();

    assertThat(this.resolver.resolve(new RequestedAttributeContext(authnRequest(null), metadata))).isEmpty();
  }

  @Test
  void theMetadataAttributesAreMapped() {
    final List<GenericRequestedAttribute> result = this.resolver.resolve(
        new RequestedAttributeContext(authnRequest(null), metadataWithRequestedAttributes(
            requestedAttribute(AttributeConstants.ATTRIBUTE_NAME_SN, true),
            requestedAttribute(AttributeConstants.ATTRIBUTE_NAME_DATE_OF_BIRTH, false))));

    assertThat(attribute(result, AttributeIdentifiers.SURNAME).isEssential()).isTrue();
    assertThat(attribute(result, AttributeIdentifiers.DATE_OF_BIRTH).isEssential()).isFalse();
  }

  @Test
  void theEntityCategoryAttributesAreMapped() {
    final List<GenericRequestedAttribute> result = this.resolver.resolve(
        new RequestedAttributeContext(authnRequest(null), metadataWithEntityCategories(LOA3_PNR)));

    assertThat(attribute(result, AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER).isEssential()).isTrue();
    assertThat(attribute(result, AttributeIdentifiers.COORDINATION_NUMBER).isEssential()).isTrue();
    assertThat(attribute(result, AttributeIdentifiers.SURNAME).isEssential()).isTrue();
    assertThat(attribute(result, AttributeIdentifiers.DATE_OF_BIRTH).isEssential()).isFalse();
  }

  @Test
  void anAttributeIsEssentialIfAnySourceSaysSo() {
    // The entity category recommends the date of birth, and the metadata requires it.
    //
    final EntityDescriptor metadata = EntityDescriptorBuilder.builder()
        .entityID(SP_ENTITY_ID)
        .extensions(ExtensionsBuilder.builder()
            .extension(EntityAttributesBuilder.builder().entityCategoriesAttribute(LOA3_PNR).build())
            .build())
        .roleDescriptors(SPSSODescriptorBuilder.builder()
            .attributeConsumingServices(AttributeConsumingServiceBuilder.builder()
                .index(0)
                .isDefault(true)
                .requestedAttributes(requestedAttribute(AttributeConstants.ATTRIBUTE_NAME_DATE_OF_BIRTH, true))
                .build())
            .build())
        .build();

    final List<GenericRequestedAttribute> result =
        this.resolver.resolve(new RequestedAttributeContext(authnRequest(null), metadata));

    assertThat(attribute(result, AttributeIdentifiers.DATE_OF_BIRTH).isEssential()).isTrue();
  }

  @Test
  void thePrincipalSelectionValuesAreCarriedOver() {
    final AuthnRequest authnRequest = authnRequest(null, PrincipalSelectionBuilder.builder()
        .matchValues(MatchValueBuilder.builder()
            .name(AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER)
            .value("196911292032")
            .build())
        .build());

    final List<GenericRequestedAttribute> result = this.resolver.resolve(
        new RequestedAttributeContext(authnRequest, metadataWithRequestedAttributes()));

    assertThat(result).singleElement().satisfies(a -> {
      assertThat(a.getIdentifier()).isEqualTo(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER);
      assertThat(a.isEssential()).isFalse();
      assertThat(a.getRequestedValues()).isEqualTo(List.of("196911292032"));
    });
  }

  @Test
  void thePrincipalSelectionValuesMeetTheAttributesOfTheOtherSources() {
    final AuthnRequest authnRequest = authnRequest(null, PrincipalSelectionBuilder.builder()
        .matchValues(MatchValueBuilder.builder()
            .name(AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER)
            .value("196911292032")
            .build())
        .build());

    final List<GenericRequestedAttribute> result = this.resolver.resolve(
        new RequestedAttributeContext(authnRequest, metadataWithRequestedAttributes(
            requestedAttribute(AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER, true))));

    assertThat(result).singleElement().satisfies(a -> {
      assertThat(a.getIdentifier()).isEqualTo(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER);
      assertThat(a.isEssential()).isTrue();
      assertThat(a.getRequestedValues()).isEqualTo(List.of("196911292032"));
    });
  }

  @Test
  void theEidasExtensionIsMappedByAnEidasProxyService() {
    final RequestedAttributes extension =
        (RequestedAttributes) XMLObjectSupport.buildXMLObject(RequestedAttributes.DEFAULT_ELEMENT_NAME);
    extension.getRequestedAttributes().add(
        eidasRequestedAttribute(EidasNaturalPersonAttributes.PERSON_IDENTIFIER.name(), true));

    final SamlRequestedAttributeResolver eidasResolver = new SamlRequestedAttributeResolver(
        new EidasAttributeMapping().getFromProtocolMapping(), SamlRequestedAttributeResolver.getDefaultProcessors(
            List.of()));

    final List<GenericRequestedAttribute> result = eidasResolver.resolve(new RequestedAttributeContext(
        authnRequest(null, extension), metadataWithRequestedAttributes()));

    assertThat(result).singleElement().satisfies(a -> {
      assertThat(a.getIdentifier()).isEqualTo(AttributeIdentifiers.EIDAS_PERSON_IDENTIFIER);
      assertThat(a.isEssential()).isTrue();
    });
  }

  @Test
  void theProcessorsAndTheMappingAreReachable() {
    final SamlAttributeMapping mapping = new SamlAttributeMapping();
    final SamlRequestedAttributeResolver own = new SamlRequestedAttributeResolver(mapping,
        List.of(new MetadataRequestedAttributeProcessor()));

    assertThat(own.getProcessors()).hasSize(1);
    assertThat(own.getAttributeMapping()).isSameAs(mapping.getFromProtocolMapping());
  }

}
