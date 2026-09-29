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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;

import se.swedenconnect.opensaml.saml2.attribute.AttributeTemplate;
import se.swedenconnect.opensaml.sweid.saml2.attribute.AttributeConstants;
import se.swedenconnect.opensaml.sweid.saml2.attribute.AttributeSet;
import se.swedenconnect.opensaml.sweid.saml2.metadata.entitycategory.EntityCategory;
import se.swedenconnect.opensaml.sweid.saml2.metadata.entitycategory.EntityCategoryConstants;
import se.swedenconnect.opensaml.sweid.saml2.metadata.entitycategory.EntityCategoryRegistryImpl;
import se.swedenconnect.opensaml.sweid.saml2.metadata.entitycategory.ServiceEntityCategory;
import se.swedenconnect.opensaml.sweid.saml2.metadata.entitycategory.ServiceEntityCategoryImpl;
import se.swedenconnect.spring.authnserver.saml.attributes.SamlRequestedAttribute;

/**
 * Tests for {@link EntityCategoryRequestedAttributeProcessor}.
 *
 * @author Martin Lindström
 */
class EntityCategoryRequestedAttributeProcessorTest extends RequestedAttributeTestSupport {

  private static final String LOA3_PNR = EntityCategoryConstants.SERVICE_ENTITY_CATEGORY_LOA3_PNR.getUri();

  private static final String LOA3_NAME = EntityCategoryConstants.SERVICE_ENTITY_CATEGORY_LOA3_NAME.getUri();

  private static List<SamlRequestedAttribute> extract(final List<String> idpCategories,
      final String... spCategories) {
    final EntityCategoryRequestedAttributeProcessor processor =
        new EntityCategoryRequestedAttributeProcessor(idpCategories);
    return processor.extractRequestedAttributes(
        new RequestedAttributeContext(authnRequest(null), metadataWithEntityCategories(spCategories)));
  }

  private static boolean required(final List<SamlRequestedAttribute> attributes, final String name) {
    return attributes.stream().filter(a -> a.name().equals(name)).findFirst().orElseThrow().required();
  }

  @Test
  void metadataWithoutEntityCategoriesGivesNothing() {
    assertThat(extract(List.of(LOA3_PNR))).isEmpty();
  }

  @Test
  void aCategoryThatTheIdentityProviderDoesNotDeclareIsIgnored() {
    assertThat(extract(List.of(LOA3_NAME), LOA3_PNR)).isEmpty();
  }

  @Test
  void aCategoryThatIsNotRegisteredIsIgnored() {
    assertThat(extract(List.of("https://example.com/ec/own"), "https://example.com/ec/own")).isEmpty();
  }

  @Test
  void aCategoryThatIsNotAServiceEntityCategoryIsIgnored() {
    final String sigService = EntityCategoryConstants.SERVICE_TYPE_CATEGORY_SIGSERVICE.getUri();
    assertThat(extract(List.of(sigService), sigService)).isEmpty();
  }

  @Test
  void oneCategoryGivesTheAttributesOfItsAttributeSet() {
    final List<SamlRequestedAttribute> result = extract(List.of(LOA3_PNR), LOA3_PNR);

    final AttributeSet attributeSet = EntityCategoryConstants.SERVICE_ENTITY_CATEGORY_LOA3_PNR.getAttributeSet();
    final List<String> expected = new ArrayList<>();
    Arrays.stream(attributeSet.getRequiredAttributes()).map(AttributeTemplate::getName).forEach(expected::add);
    Arrays.stream(attributeSet.getRecommendedAttributes()).map(AttributeTemplate::getName).forEach(expected::add);

    assertThat(names(result)).containsExactlyInAnyOrderElementsOf(expected);
    for (final AttributeTemplate template : attributeSet.getRequiredAttributes()) {
      assertThat(required(result, template.getName())).as(template.getFriendlyName()).isTrue();
    }
    for (final AttributeTemplate template : attributeSet.getRecommendedAttributes()) {
      assertThat(required(result, template.getName())).as(template.getFriendlyName()).isFalse();
    }
  }

  @Test
  void withSeveralCategoriesAnAttributeIsRequiredOnlyWhenEveryCategoryRequiresIt() {
    final List<SamlRequestedAttribute> result = extract(List.of(LOA3_PNR, LOA3_NAME), LOA3_PNR, LOA3_NAME);

    // Required by both categories.
    assertThat(required(result, AttributeConstants.ATTRIBUTE_NAME_SN)).isTrue();
    assertThat(required(result, AttributeConstants.ATTRIBUTE_NAME_GIVEN_NAME)).isTrue();
    assertThat(required(result, AttributeConstants.ATTRIBUTE_NAME_DISPLAY_NAME)).isTrue();

    // Required by loa3-pnr, but not part of loa3-name at all.
    assertThat(required(result, AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER)).isFalse();

    // Recommended by loa3-pnr.
    assertThat(required(result, AttributeConstants.ATTRIBUTE_NAME_DATE_OF_BIRTH)).isFalse();
  }

  @Test
  void anAttributeThatOneCategoryRecommendsIsNotRequired() {
    final ServiceEntityCategory recommending = new ServiceEntityCategoryImpl(
        "https://example.com/ec/recommends-sn",
        List.of("http://id.elegnamnden.se/loa/1.0/loa3"),
        new RecommendingAttributeSet());

    final EntityCategoryRequestedAttributeProcessor processor =
        new EntityCategoryRequestedAttributeProcessor(List.of(LOA3_NAME, recommending.getUri()));
    final List<EntityCategory> categories = new ArrayList<>(
        EntityCategoryRequestedAttributeProcessor.getDefaultEntityCategories());
    categories.add(recommending);
    processor.setEntityCategoryRegistry(new EntityCategoryRegistryImpl(categories));

    final List<SamlRequestedAttribute> result = processor.extractRequestedAttributes(
        new RequestedAttributeContext(authnRequest(null),
            metadataWithEntityCategories(LOA3_NAME, recommending.getUri())));

    assertThat(required(result, AttributeConstants.ATTRIBUTE_NAME_SN)).isFalse();
  }

  /**
   * An attribute set recommending, rather than requiring, the surname.
   */
  private static class RecommendingAttributeSet implements AttributeSet {

    @Override
    public String getIdentifier() {
      return "recommending";
    }

    @Override
    public String getUri() {
      return "https://example.com/attribute-set/recommending";
    }

    @Override
    public String getFriendlyName() {
      return "recommending";
    }

    @Override
    public AttributeTemplate[] getRequiredAttributes() {
      return new AttributeTemplate[] {};
    }

    @Override
    public AttributeTemplate[] getRecommendedAttributes() {
      return new AttributeTemplate[] {
          new AttributeTemplate(AttributeConstants.ATTRIBUTE_NAME_SN, AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_SN) };
    }

    @Override
    public void validateAttributes(final org.opensaml.saml.saml2.core.Assertion assertion,
        final List<org.opensaml.saml.saml2.metadata.RequestedAttribute> requestedAttributes) {
    }

  }

}
