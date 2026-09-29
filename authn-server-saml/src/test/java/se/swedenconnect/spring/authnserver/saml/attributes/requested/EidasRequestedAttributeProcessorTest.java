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

import se.swedenconnect.opensaml.eidas.ext.RequestedAttributes;
import se.swedenconnect.spring.authnserver.saml.attributes.SamlRequestedAttribute;
import se.swedenconnect.spring.authnserver.saml.attributes.eidas.EidasNaturalPersonAttributes;

/**
 * Tests for {@link EidasRequestedAttributeProcessor}.
 *
 * @author Martin Lindström
 */
class EidasRequestedAttributeProcessorTest extends RequestedAttributeTestSupport {

  private final EidasRequestedAttributeProcessor processor = new EidasRequestedAttributeProcessor();

  @Test
  void aRequestWithoutExtensionsGivesNothing() {
    final RequestedAttributeContext context =
        new RequestedAttributeContext(authnRequest(null), metadataWithRequestedAttributes());

    assertThat(this.processor.extractRequestedAttributes(context)).isEmpty();
  }

  @Test
  void aRequestWithoutTheExtensionGivesNothing() {
    final RequestedAttributeContext context = new RequestedAttributeContext(
        authnRequest(null, XMLObjectSupport.buildXMLObject(
            org.opensaml.saml.ext.reqattr.RequestedAttributes.DEFAULT_ELEMENT_NAME)),
        metadataWithRequestedAttributes());

    assertThat(this.processor.extractRequestedAttributes(context)).isEmpty();
  }

  @Test
  void theRequestedAttributesAreTakenFromTheExtension() {
    final RequestedAttributes extension =
        (RequestedAttributes) XMLObjectSupport.buildXMLObject(RequestedAttributes.DEFAULT_ELEMENT_NAME);
    extension.getRequestedAttributes().add(
        eidasRequestedAttribute(EidasNaturalPersonAttributes.PERSON_IDENTIFIER.name(), true));
    extension.getRequestedAttributes().add(
        eidasRequestedAttribute(EidasNaturalPersonAttributes.BIRTH_NAME.name(), false));

    final RequestedAttributeContext context =
        new RequestedAttributeContext(authnRequest(null, extension), metadataWithRequestedAttributes());

    final List<SamlRequestedAttribute> result = this.processor.extractRequestedAttributes(context);

    assertThat(result).hasSize(2);
    assertThat(result.getFirst().name()).isEqualTo(EidasNaturalPersonAttributes.PERSON_IDENTIFIER.name());
    assertThat(result.getFirst().required()).isTrue();
    assertThat(result.getLast().required()).isFalse();
  }

}
