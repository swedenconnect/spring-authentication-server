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
package se.swedenconnect.spring.authnserver.oidc.attributes.requested;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.Test;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;

import se.oidc.nimbus.claims.OidcScopeValue;
import se.oidc.nimbus.claims.OidcScopeValue.ClaimRequirement;
import se.swedenconnect.spring.authnserver.attributes.AttributeDefinition;
import se.swedenconnect.spring.authnserver.attributes.AttributeIdentifiers;
import se.swedenconnect.spring.authnserver.attributes.DefaultAttributeDefinitionRegistry;
import se.swedenconnect.spring.authnserver.attributes.GenericRequestedAttribute;
import se.swedenconnect.spring.authnserver.oidc.attributes.ClaimDeliveryTarget;
import se.swedenconnect.spring.authnserver.oidc.attributes.OidcAttributeMapping;
import se.swedenconnect.spring.authnserver.oidc.attributes.RequestedClaim;
import se.swedenconnect.spring.authnserver.oidc.attributes.mapping.ClaimFromProtocolMapper;
import se.swedenconnect.spring.authnserver.oidc.scope.BuiltInScopes;
import se.swedenconnect.spring.authnserver.oidc.scope.DefaultScopeRegistry;
import se.swedenconnect.spring.authnserver.oidc.scope.ScopeRegistry;

/**
 * Tests for {@link OidcRequestedAttributeResolver}.
 *
 * @author Martin Lindström
 */
class OidcRequestedAttributeResolverTest {

  private static final String LOG_STRING = "client: 'https://client.example.com'";

  private final OidcRequestedAttributeResolver resolver = new OidcRequestedAttributeResolver();

  private List<GenericRequestedAttribute> resolve(final String scope, final String claims) throws ParseException {
    return this.resolver.resolve(scope != null ? Scope.parse(scope) : null,
        claims != null ? OIDCClaimsRequest.parse(claims) : null, LOG_STRING);
  }

  private static GenericRequestedAttribute attribute(final List<GenericRequestedAttribute> attributes,
      final String identifier) {
    return attributes.stream().filter(a -> a.getIdentifier().equals(identifier)).findFirst().orElse(null);
  }

  private static ClaimDeliveryTarget target(final List<GenericRequestedAttribute> attributes,
      final String identifier) {
    return attribute(attributes, identifier)
        .getProtocolData(ClaimDeliveryTarget.PROTOCOL_DATA_KEY, ClaimDeliveryTarget.class);
  }

  private static List<String> claimNames(final List<RequestedClaim> claims) {
    return claims.stream().map(RequestedClaim::name).toList();
  }

  // ---- Scopes ----

  @Test
  void aRequestThatAsksForNothingGivesNothing() throws Exception {
    assertThat(this.resolve(null, null)).isEmpty();
    assertThat(this.resolve("", null)).isEmpty();
  }

  @Test
  void theOpenIdScopeAsksForNoUserAttributes() throws Exception {
    assertThat(this.resolve("openid", null)).isEmpty();
  }

  @Test
  void anUnknownScopeAsksForNothing() throws Exception {
    assertThat(this.resolve("openid https://example.com/scope/unknown", null)).isEmpty();
  }

  @Test
  void theProfileScopeExpandsToItsClaims() throws Exception {
    final List<GenericRequestedAttribute> result = this.resolve("openid profile", null);

    assertThat(result).extracting(GenericRequestedAttribute::getIdentifier)
        .contains(AttributeIdentifiers.DISPLAY_NAME, AttributeIdentifiers.SURNAME, AttributeIdentifiers.GIVEN_NAME,
            AttributeIdentifiers.MIDDLE_NAME, AttributeIdentifiers.NICKNAME,
            AttributeIdentifiers.PREFERRED_USERNAME, AttributeIdentifiers.PROFILE, AttributeIdentifiers.PICTURE,
            AttributeIdentifiers.WEBSITE, AttributeIdentifiers.GENDER, AttributeIdentifiers.DATE_OF_BIRTH,
            AttributeIdentifiers.ZONE_INFO, AttributeIdentifiers.LOCALE, AttributeIdentifiers.UPDATED_AT);
    assertThat(result).noneMatch(GenericRequestedAttribute::isEssential);
    assertThat(target(result, AttributeIdentifiers.SURNAME)).isEqualTo(ClaimDeliveryTarget.USER_INFO);
  }

  @Test
  void theEmailAndPhoneScopesExpandToTheirClaims() throws Exception {
    final List<GenericRequestedAttribute> result = this.resolve("openid email phone", null);

    assertThat(result).extracting(GenericRequestedAttribute::getIdentifier)
        .contains(AttributeIdentifiers.EMAIL, AttributeIdentifiers.EMAIL_VERIFIED,
            AttributeIdentifiers.TELEPHONE_NUMBER, AttributeIdentifiers.MOBILE_NUMBER,
            AttributeIdentifiers.PHONE_NUMBER_VERIFIED);
  }

  @Test
  void theAddressScopeExpandsToThePartsOfTheAddress() throws Exception {
    final List<GenericRequestedAttribute> result = this.resolve("openid address", null);

    assertThat(result).extracting(GenericRequestedAttribute::getIdentifier)
        .contains(AttributeIdentifiers.FORMATTED_ADDRESS, AttributeIdentifiers.STREET_ADDRESS,
            AttributeIdentifiers.POSTAL_CODE, AttributeIdentifiers.LOCALITY, AttributeIdentifiers.REGION,
            AttributeIdentifiers.COUNTRY, AttributeIdentifiers.EIDAS_ADDRESS_PO_BOX);
  }

  @Test
  void theNaturalPersonInfoScopeExpandsToItsClaims() throws Exception {
    final List<GenericRequestedAttribute> result =
        this.resolve("openid https://id.oidc.se/scope/naturalPersonInfo", null);

    assertThat(result).extracting(GenericRequestedAttribute::getIdentifier)
        .containsExactlyInAnyOrder(AttributeIdentifiers.SURNAME, AttributeIdentifiers.GIVEN_NAME,
            AttributeIdentifiers.MIDDLE_NAME, AttributeIdentifiers.DISPLAY_NAME, AttributeIdentifiers.DATE_OF_BIRTH);
    assertThat(result).noneMatch(GenericRequestedAttribute::isEssential);
    assertThat(result).allSatisfy(a -> assertThat(
        a.getProtocolData(ClaimDeliveryTarget.PROTOCOL_DATA_KEY, ClaimDeliveryTarget.class))
        .isEqualTo(ClaimDeliveryTarget.USER_INFO));
  }

  @Test
  void theNaturalPersonNumberScopeIsEssentialAndDeliveredInBothPlaces() throws Exception {
    final List<GenericRequestedAttribute> result =
        this.resolve("openid https://id.oidc.se/scope/naturalPersonNumber", null);

    assertThat(result).extracting(GenericRequestedAttribute::getIdentifier)
        .containsExactlyInAnyOrder(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER,
            AttributeIdentifiers.COORDINATION_NUMBER);
    assertThat(result).allMatch(GenericRequestedAttribute::isEssential);
    assertThat(target(result, AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER))
        .isEqualTo(ClaimDeliveryTarget.ID_TOKEN_AND_USER_INFO);
  }

  @Test
  void theOrganizationalIdentityScopeFollowsTheSpecification() throws Exception {
    final List<GenericRequestedAttribute> result =
        this.resolve("openid https://id.oidc.se/scope/naturalPersonOrgId", null);

    assertThat(result).extracting(GenericRequestedAttribute::getIdentifier)
        .containsExactlyInAnyOrder(AttributeIdentifiers.ORGANIZATIONAL_AFFILIATION,
            AttributeIdentifiers.DISPLAY_NAME, AttributeIdentifiers.ORGANIZATION_NAME,
            AttributeIdentifiers.ORGANIZATION_IDENTIFIER);
    assertThat(attribute(result, AttributeIdentifiers.ORGANIZATIONAL_AFFILIATION).isEssential()).isTrue();
    assertThat(target(result, AttributeIdentifiers.ORGANIZATIONAL_AFFILIATION))
        .isEqualTo(ClaimDeliveryTarget.ID_TOKEN_AND_USER_INFO);
    assertThat(attribute(result, AttributeIdentifiers.DISPLAY_NAME).isEssential()).isFalse();
    assertThat(target(result, AttributeIdentifiers.DISPLAY_NAME)).isEqualTo(ClaimDeliveryTarget.USER_INFO);
  }

  @Test
  void theSignScopeAsksForTheUserSignatureInTheIdToken() throws Exception {
    final List<GenericRequestedAttribute> result = this.resolve("openid https://id.oidc.se/scope/sign", null);

    assertThat(result).singleElement().satisfies(a -> {
      assertThat(a.getIdentifier()).isEqualTo(AttributeIdentifiers.USER_SIGNATURE);
      assertThat(a.isEssential()).isTrue();
      assertThat(a.getProtocolData(ClaimDeliveryTarget.PROTOCOL_DATA_KEY, ClaimDeliveryTarget.class))
          .isEqualTo(ClaimDeliveryTarget.ID_TOKEN);
    });
  }

  @Test
  void theSignApprovalScopeAsksForNoAttributes() throws Exception {
    assertThat(this.resolve("openid https://id.oidc.se/scope/signApproval", null)).isEmpty();
  }

  @Test
  void theEidasNaturalPersonIdentityScopeFollowsTheSpecification() throws Exception {
    final List<GenericRequestedAttribute> result = this.resolve(
        "openid " + BuiltInScopes.EIDAS_NATURAL_PERSON_IDENTITY.getValue(), null);

    assertThat(result).extracting(GenericRequestedAttribute::getIdentifier)
        .containsExactlyInAnyOrder(AttributeIdentifiers.PRID, AttributeIdentifiers.PRID_PERSISTENCE,
            AttributeIdentifiers.EIDAS_PERSON_IDENTIFIER);
    assertThat(result).allMatch(GenericRequestedAttribute::isEssential);
    assertThat(target(result, AttributeIdentifiers.PRID)).isEqualTo(ClaimDeliveryTarget.ID_TOKEN_AND_USER_INFO);
    assertThat(target(result, AttributeIdentifiers.EIDAS_PERSON_IDENTIFIER))
        .isEqualTo(ClaimDeliveryTarget.USER_INFO);
  }

  @Test
  void theEidasSwedishIdentityScopeFollowsTheSpecification() throws Exception {
    final List<GenericRequestedAttribute> result = this.resolve(
        "openid " + BuiltInScopes.EIDAS_SWEDISH_IDENTITY.getValue(), null);

    assertThat(result).extracting(GenericRequestedAttribute::getIdentifier)
        .containsExactlyInAnyOrder(AttributeIdentifiers.MAPPED_PERSONAL_IDENTITY_NUMBER,
            AttributeIdentifiers.MAPPED_COORDINATION_NUMBER, AttributeIdentifiers.IDENTITY_BINDING);
    assertThat(result).noneMatch(GenericRequestedAttribute::isEssential);
    assertThat(target(result, AttributeIdentifiers.IDENTITY_BINDING)).isEqualTo(ClaimDeliveryTarget.USER_INFO);
  }

  // ---- The claims request parameter ----

  @Test
  void theClaimsRequestParameterIsMerged() throws Exception {
    final List<GenericRequestedAttribute> result = this.resolve("openid",
        """
            {
              "id_token" : { "https://id.oidc.se/claim/personalIdentityNumber" : { "essential" : true } },
              "userinfo" : { "given_name" : null }
            }
            """);

    assertThat(result).extracting(GenericRequestedAttribute::getIdentifier)
        .containsExactlyInAnyOrder(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER, AttributeIdentifiers.GIVEN_NAME);
    assertThat(attribute(result, AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER).isEssential()).isTrue();
    assertThat(target(result, AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER)).isEqualTo(ClaimDeliveryTarget.ID_TOKEN);
    assertThat(target(result, AttributeIdentifiers.GIVEN_NAME)).isEqualTo(ClaimDeliveryTarget.USER_INFO);
  }

  @Test
  void aClaimOfTheIdTokenIsAlsoDeliveredFromUserInfoWhenAScopeCoversIt() throws Exception {
    final List<GenericRequestedAttribute> result = this.resolve("openid profile",
        """
            { "id_token" : { "family_name" : { "essential" : true } } }
            """);

    assertThat(target(result, AttributeIdentifiers.SURNAME))
        .isEqualTo(ClaimDeliveryTarget.ID_TOKEN_AND_USER_INFO);
    assertThat(attribute(result, AttributeIdentifiers.SURNAME).isEssential()).isTrue();
    assertThat(attribute(result, AttributeIdentifiers.GIVEN_NAME).isEssential()).isFalse();
    assertThat(target(result, AttributeIdentifiers.GIVEN_NAME)).isEqualTo(ClaimDeliveryTarget.USER_INFO);
  }

  @Test
  void aClaimOfTheIdTokenIsDeliveredThereAloneWhenNoScopeCoversIt() throws Exception {
    final List<GenericRequestedAttribute> result = this.resolve("openid",
        """
            { "id_token" : { "family_name" : { "essential" : true } } }
            """);

    assertThat(target(result, AttributeIdentifiers.SURNAME)).isEqualTo(ClaimDeliveryTarget.ID_TOKEN);
  }

  @Test
  void anAttributeIsEssentialIfAnySourceSaysSo() throws Exception {
    final List<GenericRequestedAttribute> result =
        this.resolve("openid profile https://id.oidc.se/scope/naturalPersonInfo",
            """
                { "userinfo" : { "birthdate" : { "essential" : true } } }
                """);

    assertThat(attribute(result, AttributeIdentifiers.DATE_OF_BIRTH).isEssential()).isTrue();
  }

  @Test
  void theRequestedValuesOfTheClaimsParameterAreCarriedOver() throws Exception {
    final List<GenericRequestedAttribute> result = this.resolve("openid",
        """
            {
              "id_token" : {
                "https://id.oidc.se/claim/personalIdentityNumber" : {
                  "essential" : true, "value" : "196911292032"
                }
              }
            }
            """);

    assertThat(attribute(result, AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER).getRequestedValues())
        .isEqualTo(List.of("196911292032"));
    assertThat(attribute(result, AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER).isRequestedValuesEssential())
        .isTrue();
  }

  @Test
  void theEntryCarryingTheValueDecidesWhetherItIsEssential() throws Exception {
    final List<GenericRequestedAttribute> result = this.resolve("openid",
        """
            {
              "id_token" : { "family_name" : { "essential" : true } },
              "userinfo" : { "family_name" : { "value" : "Ekvall" } }
            }
            """);

    final GenericRequestedAttribute surname = attribute(result, AttributeIdentifiers.SURNAME);
    assertThat(surname.isEssential()).isTrue();
    assertThat(surname.getRequestedValues()).isEqualTo(List.of("Ekvall"));
    assertThat(surname.isRequestedValuesEssential()).isFalse();
  }

  @Test
  void aScopeMarkingTheClaimEssentialMakesAVoluntaryValueEssential() throws Exception {
    final String claims = """
        {
          "userinfo" : { "https://id.oidc.se/claim/personalIdentityNumber" : { "value" : "196911292032" } }
        }
        """;
    assertThat(attribute(this.resolve("openid", claims), AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER)
        .isRequestedValuesEssential()).isFalse();
    assertThat(attribute(this.resolve("openid https://id.oidc.se/scope/naturalPersonNumber", claims),
        AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER).isRequestedValuesEssential()).isTrue();
    // A scope that does not mark the claim essential does not
    assertThat(attribute(this.resolve("openid profile", """
        { "userinfo" : { "family_name" : { "value" : "Ekvall" } } }
        """), AttributeIdentifiers.SURNAME).isRequestedValuesEssential()).isFalse();
  }

  @Test
  void claimsThatAreNotUserAttributesAreLeftOut() throws Exception {
    final List<GenericRequestedAttribute> result = this.resolve("openid https://id.oidc.se/scope/sign",
        """
            { "id_token" : { "sub" : { "essential" : true }, "acr" : null } }
            """);

    assertThat(result).extracting(GenericRequestedAttribute::getIdentifier)
        .containsExactly(AttributeIdentifiers.USER_SIGNATURE);
  }

  @Test
  void theRequestedClaimsHoldOneEntryPerSource() throws Exception {
    final List<RequestedClaim> claims = this.resolver.getRequestedClaims(
        Scope.parse("openid https://id.oidc.se/scope/sign"),
        OIDCClaimsRequest.parse("{ \"id_token\" : { \"auth_time\" : { \"essential\" : true } } }"), LOG_STRING);

    assertThat(claimNames(claims)).containsExactly("sub", "https://id.oidc.se/claim/userSignature", "auth_time",
        "auth_time");
  }

  // ---- Scopes and mappers of the application ----

  @Test
  void anOwnScopeIsUsed() throws Exception {
    final DefaultAttributeDefinitionRegistry definitions = new DefaultAttributeDefinitionRegistry();
    definitions.register(AttributeDefinition.ofString("attribute.employee-number", "Employee number."));

    final OidcAttributeMapping mapping = new OidcAttributeMapping(definitions);
    mapping.getFromProtocolMapping().register(
        new ClaimFromProtocolMapper("https://example.com/claim/employeeNumber", "attribute.employee-number"));

    final ScopeRegistry scopes = new DefaultScopeRegistry();
    scopes.register(new OidcScopeValue("https://example.com/scope/employee", new ClaimRequirement[] {
        ClaimRequirement.of("https://example.com/claim/employeeNumber", true, true, false) }));

    final OidcRequestedAttributeResolver ownResolver = new OidcRequestedAttributeResolver(mapping, scopes);
    final List<GenericRequestedAttribute> result = ownResolver.resolve(
        Scope.parse("openid https://example.com/scope/employee"), null, LOG_STRING);

    assertThat(result).singleElement().satisfies(a -> {
      assertThat(a.getIdentifier()).isEqualTo("attribute.employee-number");
      assertThat(a.isEssential()).isTrue();
      assertThat(a.getProtocolData(ClaimDeliveryTarget.PROTOCOL_DATA_KEY, ClaimDeliveryTarget.class))
          .isEqualTo(ClaimDeliveryTarget.ID_TOKEN);
    });
  }

  @Test
  void theScopeRegistryAndTheMappingAreReachable() {
    assertThat(this.resolver.getScopeRegistry()).isNotNull();
    assertThat(this.resolver.getAttributeMapping()).isNotNull();
  }

}
