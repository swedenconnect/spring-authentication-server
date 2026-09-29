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

import se.swedenconnect.opensaml.sweid.saml2.attribute.AttributeConstants;
import se.swedenconnect.opensaml.sweid.saml2.authn.psc.build.MatchValueBuilder;
import se.swedenconnect.opensaml.sweid.saml2.authn.psc.build.PrincipalSelectionBuilder;
import se.swedenconnect.spring.authnserver.saml.attributes.SamlRequestedAttribute;

/**
 * Tests for {@link PrincipalSelectionRequestedAttributeProcessor}.
 *
 * @author Martin Lindström
 */
class PrincipalSelectionRequestedAttributeProcessorTest extends RequestedAttributeTestSupport {

  private final PrincipalSelectionRequestedAttributeProcessor processor =
      new PrincipalSelectionRequestedAttributeProcessor();

  @Test
  void aRequestWithoutTheExtensionGivesNothing() {
    final RequestedAttributeContext context =
        new RequestedAttributeContext(authnRequest(null), metadataWithRequestedAttributes());

    assertThat(this.processor.extractRequestedAttributes(context)).isEmpty();
  }

  @Test
  void theMatchValuesBecomeRequestedAttributesThatAreNotRequired() {
    final RequestedAttributeContext context = new RequestedAttributeContext(
        authnRequest(null, PrincipalSelectionBuilder.builder()
            .matchValues(
                MatchValueBuilder.builder()
                    .name(AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER)
                    .value("196911292032")
                    .build(),
                MatchValueBuilder.builder()
                    .name(AttributeConstants.ATTRIBUTE_NAME_DISPLAY_NAME)
                    .value("Elsa Ekvall")
                    .build())
            .build()),
        metadataWithRequestedAttributes());

    final List<SamlRequestedAttribute> result = this.processor.extractRequestedAttributes(context);

    assertThat(result).hasSize(2);
    assertThat(result.getFirst().name()).isEqualTo(AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER);
    assertThat(result.getFirst().required()).isFalse();
    assertThat(result.getFirst().stringValues()).containsExactly("196911292032");
    assertThat(result.getLast().stringValues()).containsExactly("Elsa Ekvall");
  }

  @Test
  void aMatchValueWithoutAValueIsIgnored() {
    final RequestedAttributeContext context = new RequestedAttributeContext(
        authnRequest(null, PrincipalSelectionBuilder.builder()
            .matchValues(MatchValueBuilder.builder()
                .name(AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER)
                .build())
            .build()),
        metadataWithRequestedAttributes());

    assertThat(this.processor.extractRequestedAttributes(context)).isEmpty();
  }

}
