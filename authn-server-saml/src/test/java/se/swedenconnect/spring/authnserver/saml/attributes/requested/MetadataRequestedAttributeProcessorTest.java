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

import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;

import se.swedenconnect.opensaml.saml2.metadata.build.AttributeConsumingServiceBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.EntityDescriptorBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.SPSSODescriptorBuilder;
import se.swedenconnect.opensaml.sweid.saml2.attribute.AttributeConstants;
import se.swedenconnect.spring.authnserver.saml.attributes.SamlRequestedAttribute;

/**
 * Tests for {@link MetadataRequestedAttributeProcessor}.
 *
 * @author Martin Lindström
 */
class MetadataRequestedAttributeProcessorTest extends RequestedAttributeTestSupport {

  private final MetadataRequestedAttributeProcessor processor = new MetadataRequestedAttributeProcessor();

  private static EntityDescriptor metadataWithServices(final int... indexes) {
    final AttributeConsumingServiceBuilder[] builders = new AttributeConsumingServiceBuilder[indexes.length];
    for (int i = 0; i < indexes.length; i++) {
      builders[i] = AttributeConsumingServiceBuilder.builder()
          .index(indexes[i])
          .isDefault(false)
          .requestedAttributes(requestedAttribute("urn:example:acs-" + indexes[i], true));
    }
    return EntityDescriptorBuilder.builder()
        .entityID(SP_ENTITY_ID)
        .roleDescriptors(SPSSODescriptorBuilder.builder()
            .attributeConsumingServices(Arrays.stream(builders)
                .map(AttributeConsumingServiceBuilder::build)
                .toList())
            .build())
        .build();
  }

  @Test
  void metadataWithoutServiceProviderRoleGivesNothing() {
    final RequestedAttributeContext context = new RequestedAttributeContext(authnRequest(null),
        EntityDescriptorBuilder.builder().entityID(SP_ENTITY_ID).build());

    assertThat(this.processor.extractRequestedAttributes(context)).isEmpty();
  }

  @Test
  void metadataWithoutAttributeConsumingServiceGivesNothing() {
    final RequestedAttributeContext context = new RequestedAttributeContext(authnRequest(null),
        EntityDescriptorBuilder.builder()
            .entityID(SP_ENTITY_ID)
            .roleDescriptors(SPSSODescriptorBuilder.builder().build())
            .build());

    assertThat(this.processor.extractRequestedAttributes(context)).isEmpty();
  }

  @Test
  void theRequestedAttributesAreTakenFromTheMetadata() {
    final RequestedAttributeContext context = new RequestedAttributeContext(authnRequest(null),
        metadataWithRequestedAttributes(
            requestedAttribute(AttributeConstants.ATTRIBUTE_NAME_SN, true),
            requestedAttribute(AttributeConstants.ATTRIBUTE_NAME_DATE_OF_BIRTH, false)));

    final List<SamlRequestedAttribute> result = this.processor.extractRequestedAttributes(context);

    assertThat(result).hasSize(2);
    assertThat(result.getFirst().name()).isEqualTo(AttributeConstants.ATTRIBUTE_NAME_SN);
    assertThat(result.getFirst().required()).isTrue();
    assertThat(result.getLast().name()).isEqualTo(AttributeConstants.ATTRIBUTE_NAME_DATE_OF_BIRTH);
    assertThat(result.getLast().required()).isFalse();
  }

  @Test
  void theIndexOfTheRequestPicksTheAttributeConsumingService() {
    final RequestedAttributeContext context =
        new RequestedAttributeContext(authnRequest(2), metadataWithServices(1, 2, 3));

    assertThat(names(this.processor.extractRequestedAttributes(context))).containsExactly("urn:example:acs-2");
  }

  @Test
  void anIndexThatTheMetadataDoesNotHoldGivesNothing() {
    final RequestedAttributeContext context =
        new RequestedAttributeContext(authnRequest(17), metadataWithServices(1, 2));

    assertThat(this.processor.extractRequestedAttributes(context)).isEmpty();
  }

  @Test
  void withoutAnIndexTheDefaultAttributeConsumingServiceIsUsed() {
    final EntityDescriptor metadata = EntityDescriptorBuilder.builder()
        .entityID(SP_ENTITY_ID)
        .roleDescriptors(SPSSODescriptorBuilder.builder()
            .attributeConsumingServices(
                AttributeConsumingServiceBuilder.builder()
                    .index(1)
                    .isDefault(false)
                    .requestedAttributes(requestedAttribute("urn:example:acs-1", true))
                    .build(),
                AttributeConsumingServiceBuilder.builder()
                    .index(2)
                    .isDefault(true)
                    .requestedAttributes(requestedAttribute("urn:example:acs-2", true))
                    .build())
            .build())
        .build();
    final RequestedAttributeContext context = new RequestedAttributeContext(authnRequest(null), metadata);

    assertThat(names(this.processor.extractRequestedAttributes(context))).containsExactly("urn:example:acs-2");
  }

  @Test
  void withoutAnIndexAndWithoutADefaultTheLowestIndexIsUsed() {
    final RequestedAttributeContext context =
        new RequestedAttributeContext(authnRequest(null), metadataWithServices(3, 1, 2));

    assertThat(names(this.processor.extractRequestedAttributes(context))).containsExactly("urn:example:acs-1");
  }

}
