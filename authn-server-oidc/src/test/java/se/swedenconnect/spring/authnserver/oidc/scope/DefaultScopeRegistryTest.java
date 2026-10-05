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
package se.swedenconnect.spring.authnserver.oidc.scope;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.Test;

import se.oidc.nimbus.claims.OidcScopeValue;
import se.oidc.nimbus.claims.OidcScopeValue.ClaimRequirement;
import se.oidc.nimbus.claims.ScopeConstants;

/**
 * Tests for {@link DefaultScopeRegistry} and {@link BuiltInScopes}.
 *
 * @author Martin Lindström
 */
class DefaultScopeRegistryTest {

  @Test
  void theBuiltInScopesAreRegistered() {
    final ScopeRegistry registry = new DefaultScopeRegistry();

    assertThat(registry.getScopes()).hasSize(BuiltInScopes.getBuiltInScopes().size());
    for (final OidcScopeValue scope : BuiltInScopes.getBuiltInScopes()) {
      assertThat(registry.getScope(scope.getValue())).isSameAs(scope);
    }
  }

  @Test
  void anUnknownScopeIsNotFound() {
    assertThat(new DefaultScopeRegistry().getScope("https://example.com/scope/unknown")).isNull();
  }

  @Test
  void aRegistryCanBeCreatedWithoutTheBuiltInScopes() {
    assertThat(new DefaultScopeRegistry(false).getScopes()).isEmpty();
    assertThat(new DefaultScopeRegistry(List.of(OidcScopeValue.PROFILE)).getScopes())
        .containsExactly(OidcScopeValue.PROFILE);
  }

  @Test
  void anOwnScopeIsRegistered() {
    final ScopeRegistry registry = new DefaultScopeRegistry();
    final OidcScopeValue own = new OidcScopeValue("https://example.com/scope/employee",
        new ClaimRequirement[] { ClaimRequirement.of("https://example.com/claim/employeeNumber", true, true, true) });
    registry.register(own);

    assertThat(registry.getScope("https://example.com/scope/employee")).isSameAs(own);
  }

  @Test
  void aRegisteredScopeReplacesTheBuiltInOne() {
    final ScopeRegistry registry = new DefaultScopeRegistry();
    final OidcScopeValue own = new OidcScopeValue(OidcScopeValue.PROFILE.getValue(),
        new ClaimRequirement[] { ClaimRequirement.of("name") });
    registry.register(own);

    assertThat(registry.getScope("profile")).isSameAs(own);
    assertThat(registry.getScopes()).hasSize(BuiltInScopes.getBuiltInScopes().size());
  }

  @Test
  void theSignApprovalScopeAsksForNoClaims() {
    assertThat(ScopeConstants.SIGN_APPROVAL.getValue()).isEqualTo("https://id.oidc.se/scope/signApproval");
    assertThat(ScopeConstants.SIGN_APPROVAL.getClaimRequirements()).isNull();
  }

  @Test
  void theEidasScopesFollowTheSpecification() {
    assertThat(BuiltInScopes.EIDAS_NATURAL_PERSON_IDENTITY.getValue())
        .isEqualTo("https://id.swedenconnect.se/scope/eidasNaturalPersonIdentity");
    assertThat(BuiltInScopes.EIDAS_NATURAL_PERSON_IDENTITY.getClaimRequirements())
        .allMatch(ClaimRequirement::essential)
        .allMatch(ClaimRequirement::defaultUserInfoDelivery)
        .anyMatch(c -> !c.defaultIdTokenDelivery());

    assertThat(BuiltInScopes.EIDAS_SWEDISH_IDENTITY.getValue())
        .isEqualTo("https://id.swedenconnect.se/scope/eidasSwedishIdentity");
    assertThat(BuiltInScopes.EIDAS_SWEDISH_IDENTITY.getClaimRequirements())
        .noneMatch(ClaimRequirement::essential)
        .noneMatch(ClaimRequirement::defaultIdTokenDelivery)
        .allMatch(ClaimRequirement::defaultUserInfoDelivery);
  }

  @Test
  void theScopesOfTheLibrariesAreUsedWhereTheyExist() {
    final ScopeRegistry registry = new DefaultScopeRegistry();

    assertThat(registry.getScope("openid")).isSameAs(OidcScopeValue.OPENID);
    assertThat(registry.getScope("https://id.oidc.se/scope/naturalPersonInfo"))
        .isSameAs(ScopeConstants.NATURAL_PERSON_INFO);
    assertThat(registry.getScope("https://id.oidc.se/scope/sign")).isSameAs(ScopeConstants.SIGN);
  }

}
