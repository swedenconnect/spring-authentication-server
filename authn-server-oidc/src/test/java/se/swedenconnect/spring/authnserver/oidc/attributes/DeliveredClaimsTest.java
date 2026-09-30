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
package se.swedenconnect.spring.authnserver.oidc.attributes;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.Serializable;
import java.util.List;

import org.junit.jupiter.api.Test;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;

import se.swedenconnect.spring.authnserver.attributes.AttributeIdentifiers;
import se.swedenconnect.spring.authnserver.attributes.GenericAttribute;
import se.swedenconnect.spring.authnserver.attributes.GenericRequestedAttribute;
import se.swedenconnect.spring.authnserver.oidc.attributes.requested.OidcRequestedAttributeResolver;

/**
 * Tests for {@link DeliveredClaims}.
 *
 * @author Martin Lindström
 */
class DeliveredClaimsTest {

  private static final List<GenericAttribute<? extends Serializable>> RELEASED = List.of(
      GenericAttribute.of(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER, "197705232382"),
      GenericAttribute.of(AttributeIdentifiers.GIVEN_NAME, "Kalle"),
      GenericAttribute.of(AttributeIdentifiers.SURNAME, "Kula"));

  private final OidcRequestedAttributeResolver resolver = new OidcRequestedAttributeResolver();

  @Test
  void claimsFollowTheirDeliveryTargets() throws Exception {
    final List<GenericRequestedAttribute> requested = this.resolver.resolve(Scope.parse("openid profile"),
        OIDCClaimsRequest.parse("{\"id_token\":{\"given_name\":null}}"), "test");
    final DeliveredClaims claims = DeliveredClaims.of(RELEASED, requested, this.resolver.getAttributeMapping());

    assertThat(claims.idToken()).containsOnlyKeys("given_name");
    assertThat(claims.userInfo()).containsKeys("given_name", "family_name")
        .doesNotContainKey("https://id.oidc.se/claim/personalIdentityNumber");
  }

  @Test
  void aClaimThatWasNotRequestedIsNotDelivered() {
    final DeliveredClaims claims = DeliveredClaims.of(RELEASED, List.of(), this.resolver.getAttributeMapping());
    assertThat(claims.idToken()).isEmpty();
    assertThat(claims.userInfo()).isEmpty();
  }

  @Test
  void aRequestedAttributeWithoutTargetGoesToUserInfo() {
    final DeliveredClaims claims = DeliveredClaims.of(RELEASED,
        List.of(GenericRequestedAttribute.of(AttributeIdentifiers.SURNAME)), this.resolver.getAttributeMapping());
    assertThat(claims.idToken()).isEmpty();
    assertThat(claims.userInfo()).containsOnlyKeys("family_name");
  }

  @Test
  void storedClaimsAreParsed() {
    assertThat(DeliveredClaims.parse("{\"a\":\"b\"}")).containsEntry("a", "b");
    assertThatThrownBy(() -> DeliveredClaims.parse("not json")).isInstanceOf(IllegalArgumentException.class);
  }

}
