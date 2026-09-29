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
package se.swedenconnect.spring.authnserver.saml.attributes.release;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.Serializable;
import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.Test;

import se.swedenconnect.opensaml.sweid.saml2.metadata.entitycategory.EntityCategoryConstants;
import se.swedenconnect.spring.authnserver.attributes.AttributeIdentifiers;
import se.swedenconnect.spring.authnserver.attributes.GenericAttribute;
import se.swedenconnect.spring.authnserver.attributes.release.AttributeReleaseVote;
import se.swedenconnect.spring.authnserver.authentication.AuthenticatedUser;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationRequirements;
import se.swedenconnect.spring.authnserver.authentication.UserAuthentication;
import se.swedenconnect.spring.authnserver.saml.authentication.SamlAuthenticationRequirements;

/**
 * Tests for {@link SwedenConnectAttributeReleaseVoter}.
 *
 * @author Martin Lindström
 */
class SwedenConnectAttributeReleaseVoterTest {

  private static final String ACCEPTS_COORDINATION_NUMBER =
      EntityCategoryConstants.GENERAL_CATEGORY_ACCEPTS_COORDINATION_NUMBER.getUri();

  private static final GenericAttribute<String> COORDINATION_NUMBER =
      GenericAttribute.of(AttributeIdentifiers.COORDINATION_NUMBER, "196911792031");

  private static final GenericAttribute<String> PERSONAL_IDENTITY_NUMBER =
      GenericAttribute.of(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER, "197705232382");

  private static final GenericAttribute<String> MAPPED_COORDINATION_NUMBER =
      GenericAttribute.of(AttributeIdentifiers.MAPPED_COORDINATION_NUMBER, "196911792031");

  private final SwedenConnectAttributeReleaseVoter voter = new SwedenConnectAttributeReleaseVoter();

  private static UserAuthentication authentication(final AuthenticationRequirements requirements) {
    final AuthenticatedUser user = new AuthenticatedUser(
        List.of(GenericAttribute.of(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER, "197705232382")),
        AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER, "http://id.elegnamnden.se/loa/1.0/loa3", Instant.now(),
        "192.168.1.14");
    final UserAuthentication authentication = new UserAuthentication(user);
    authentication.registerUse(AuthenticationProtocol.SAML, "https://sp.example.com/sp", "_1", List.of());
    authentication.setAuthnRequirements(requirements);
    return authentication;
  }

  private static UserAuthentication samlAuthentication(final String... entityCategories) {
    final SamlAuthenticationRequirements requirements = new SamlAuthenticationRequirements();
    requirements.setEntityCategories(List.of(entityCategories));
    return authentication(requirements);
  }

  private AttributeReleaseVote vote(final UserAuthentication authentication,
      final GenericAttribute<? extends Serializable> attribute) {
    return this.voter.vote(authentication, attribute);
  }

  @Test
  void aCoordinationNumberIsReleasedToAnSpThatHasOptedIn() {
    assertThat(this.vote(samlAuthentication(ACCEPTS_COORDINATION_NUMBER), COORDINATION_NUMBER))
        .isEqualTo(AttributeReleaseVote.DONT_KNOW);
  }

  @Test
  void aCoordinationNumberIsWithheldFromAnSpThatHasNotOptedIn() {
    assertThat(this.vote(samlAuthentication(), COORDINATION_NUMBER))
        .isEqualTo(AttributeReleaseVote.DONT_INCLUDE);
    assertThat(this.vote(samlAuthentication("http://id.elegnamnden.se/ec/1.0/loa3-pnr"), COORDINATION_NUMBER))
        .isEqualTo(AttributeReleaseVote.DONT_INCLUDE);
  }

  @Test
  void aPersonalIdentityNumberIsNotAffectedByTheOptIn() {
    assertThat(this.vote(samlAuthentication(), PERSONAL_IDENTITY_NUMBER))
        .isEqualTo(AttributeReleaseVote.DONT_KNOW);
    assertThat(this.vote(samlAuthentication(ACCEPTS_COORDINATION_NUMBER), PERSONAL_IDENTITY_NUMBER))
        .isEqualTo(AttributeReleaseVote.DONT_KNOW);
  }

  @Test
  void theMappedCoordinationNumberIsNotCoveredByTheOptIn() {
    assertThat(this.vote(samlAuthentication(), MAPPED_COORDINATION_NUMBER))
        .isEqualTo(AttributeReleaseVote.DONT_KNOW);
  }

  @Test
  void requirementsThatAreNotSamlMeanNoDeclaredCategories() {
    assertThat(this.vote(authentication(new AuthenticationRequirements()), COORDINATION_NUMBER))
        .isEqualTo(AttributeReleaseVote.DONT_INCLUDE);
  }

  @Test
  void anAttributeThatTheRuleDoesNotCoverIsLeftToTheOtherVoters() {
    assertThat(this.vote(samlAuthentication(),
        GenericAttribute.of(AttributeIdentifiers.SURNAME, "Andersson")))
        .isEqualTo(AttributeReleaseVote.DONT_KNOW);
  }

}
