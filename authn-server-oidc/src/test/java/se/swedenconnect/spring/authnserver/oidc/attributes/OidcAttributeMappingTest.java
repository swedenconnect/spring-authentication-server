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

import java.io.Serializable;
import java.time.Instant;
import java.time.LocalDate;
import java.util.Collection;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.claims.Address;
import com.nimbusds.openid.connect.sdk.claims.ClaimRequirement;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import com.nimbusds.openid.connect.sdk.claims.PersonClaims;

import net.minidev.json.JSONObject;

import se.oidc.nimbus.claims.ClaimConstants;
import se.swedenconnect.spring.authnserver.attributes.AttributeIdentifiers;
import se.swedenconnect.spring.authnserver.attributes.GenericAttribute;
import se.swedenconnect.spring.authnserver.attributes.GenericRequestedAttribute;
import se.swedenconnect.spring.authnserver.attributes.mapping.ToProtocolAttributeMapper;
import se.swedenconnect.spring.authnserver.attributes.mapping.ToProtocolMappingContext;
import se.swedenconnect.spring.authnserver.oidc.attributes.mapping.ClaimToProtocolMapper;

/**
 * Tests for {@link OidcAttributeMapping}.
 *
 * @author Martin Lindström
 */
class OidcAttributeMappingTest {

  private OidcAttributeMapping mapping;

  @BeforeEach
  void setup() {
    this.mapping = new OidcAttributeMapping();
  }

  private static RequestedClaim requested(final String name, final boolean essential,
      final ClaimDeliveryTarget target) {
    ClaimsSetRequest.Entry entry = new ClaimsSetRequest.Entry(name);
    if (essential) {
      entry = entry.withClaimRequirement(ClaimRequirement.ESSENTIAL);
    }
    return new RequestedClaim(entry, target);
  }

  private List<String> identifiers(final List<GenericRequestedAttribute> attributes) {
    return attributes.stream().map(GenericRequestedAttribute::getIdentifier).toList();
  }

  private Object claim(final List<UserClaim> claims, final String name) {
    return claims.stream().filter(c -> c.name().equals(name)).map(UserClaim::value).findFirst().orElse(null);
  }

  // ---- From OpenID Connect ----

  @Test
  void aSimpleRequestedClaimIsMapped() {
    final List<GenericRequestedAttribute> result = this.mapping.toGeneric(
        List.of(requested(PersonClaims.FAMILY_NAME_CLAIM_NAME, true, ClaimDeliveryTarget.ID_TOKEN)));

    assertThat(result).singleElement().satisfies(a -> {
      assertThat(a.getIdentifier()).isEqualTo(AttributeIdentifiers.SURNAME);
      assertThat(a.isEssential()).isTrue();
      assertThat(a.getProtocolData(ClaimDeliveryTarget.PROTOCOL_DATA_KEY, ClaimDeliveryTarget.class))
          .isEqualTo(ClaimDeliveryTarget.ID_TOKEN);
    });
  }

  @Test
  void aRequestedPhoneNumberBecomesBothTelephoneAndMobile() {
    assertThat(this.identifiers(this.mapping.toGeneric(
        List.of(requested(PersonClaims.PHONE_NUMBER_CLAIM_NAME, false, ClaimDeliveryTarget.USER_INFO)))))
        .containsExactlyInAnyOrder(
            AttributeIdentifiers.TELEPHONE_NUMBER, AttributeIdentifiers.MOBILE_NUMBER);
  }

  @Test
  void aRequestedAddressBecomesItsParts() {
    assertThat(this.identifiers(this.mapping.toGeneric(
        List.of(requested(PersonClaims.ADDRESS_CLAIM_NAME, false, ClaimDeliveryTarget.USER_INFO)))))
        .containsExactlyInAnyOrder(AttributeIdentifiers.FORMATTED_ADDRESS, AttributeIdentifiers.STREET_ADDRESS,
            AttributeIdentifiers.POST_OFFICE_BOX, AttributeIdentifiers.POSTAL_CODE, AttributeIdentifiers.LOCALITY,
            AttributeIdentifiers.REGION, AttributeIdentifiers.COUNTRY);
  }

  @Test
  void aClaimRequestedInBothSectionsGetsTheIdTokenAsTarget() {
    final List<GenericRequestedAttribute> result = this.mapping.toGeneric(List.of(
        requested(PersonClaims.FAMILY_NAME_CLAIM_NAME, false, ClaimDeliveryTarget.USER_INFO),
        requested(PersonClaims.FAMILY_NAME_CLAIM_NAME, true, ClaimDeliveryTarget.ID_TOKEN)));

    assertThat(result).singleElement().satisfies(a -> {
      assertThat(a.isEssential()).isTrue();
      assertThat(a.getProtocolData(ClaimDeliveryTarget.PROTOCOL_DATA_KEY, ClaimDeliveryTarget.class))
          .isEqualTo(ClaimDeliveryTarget.ID_TOKEN);
    });
  }

  @Test
  void aRequestedClaimThatNoMapperHandlesIsLeftOut() {
    assertThat(this.mapping.toGeneric(
        List.of(requested("https://example.com/claim/whatever", true, ClaimDeliveryTarget.ID_TOKEN)))).isEmpty();
  }

  @Test
  void requestedValuesAreCarriedOver() {
    final ClaimsSetRequest.Entry entry = new ClaimsSetRequest.Entry(
        ClaimConstants.PERSONAL_IDENTITY_NUMBER_CLAIM_NAME).withValue("195006262546");
    final List<GenericRequestedAttribute> result = this.mapping.toGeneric(
        List.of(new RequestedClaim(entry, ClaimDeliveryTarget.ID_TOKEN)));

    assertThat(result).singleElement()
        .extracting(GenericRequestedAttribute::getRequestedValues)
        .isEqualTo(List.of("195006262546"));
  }

  @Test
  void severalRequestedValuesAreCarriedOver() {
    final ClaimsSetRequest.Entry entry = new ClaimsSetRequest.Entry(PersonClaims.GENDER_CLAIM_NAME)
        .withValues(List.of("female", "male"));
    final List<GenericRequestedAttribute> result = this.mapping.toGeneric(
        List.of(new RequestedClaim(entry, ClaimDeliveryTarget.USER_INFO)));

    assertThat(result).singleElement()
        .extracting(GenericRequestedAttribute::getRequestedValues)
        .isEqualTo(List.of("female", "male"));
  }

  @Test
  void theValueOfAnObjectClaimIsNotCarriedToItsParts() {
    final ClaimsSetRequest.Entry entry = new ClaimsSetRequest.Entry(PersonClaims.ADDRESS_CLAIM_NAME)
        .withValue(new JSONObject(java.util.Map.of("country", "SE")));
    final List<GenericRequestedAttribute> result = this.mapping.toGeneric(
        List.of(new RequestedClaim(entry, ClaimDeliveryTarget.USER_INFO)));

    assertThat(result).isNotEmpty().allMatch(a -> a.getRequestedValues().isEmpty());
  }

  @Test
  void aClaimsRequestParameterIsMapped() throws Exception {
    final OIDCClaimsRequest claimsRequest = OIDCClaimsRequest.parse("""
        {
          "id_token" : { "https://id.oidc.se/claim/personalIdentityNumber" : { "essential" : true } },
          "userinfo" : { "family_name" : null, "given_name" : null }
        }
        """);
    final List<GenericRequestedAttribute> result = this.mapping.toGenericFromClaimsRequest(claimsRequest);

    assertThat(this.identifiers(result)).containsExactlyInAnyOrder(
        AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER, AttributeIdentifiers.SURNAME,
        AttributeIdentifiers.GIVEN_NAME);
    assertThat(result.stream()
        .filter(a -> a.getIdentifier().equals(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER))
        .findFirst().orElseThrow()
        .getProtocolData(ClaimDeliveryTarget.PROTOCOL_DATA_KEY, ClaimDeliveryTarget.class))
        .isEqualTo(ClaimDeliveryTarget.ID_TOKEN);
  }

  @Test
  void noClaimsRequestGivesNoResult() {
    assertThat(this.mapping.toGenericFromClaimsRequest(null)).isEmpty();
  }

  // ---- To OpenID Connect ----

  @Test
  void aSimpleAttributeIsMapped() {
    assertThat(this.claim(this.mapping.toClaims(
        List.of(GenericAttribute.of(AttributeIdentifiers.SURNAME, "Lindeman")), null),
        PersonClaims.FAMILY_NAME_CLAIM_NAME))
        .isEqualTo("Lindeman");
  }

  @Test
  void aDateBecomesAnIsoStringAndAnInstantSecondsSinceEpoch() {
    assertThat(this.claim(this.mapping.toClaims(
        List.of(GenericAttribute.of(AttributeIdentifiers.DATE_OF_BIRTH, LocalDate.of(1950, 6, 26))), null),
        PersonClaims.BIRTHDATE_CLAIM_NAME))
        .isEqualTo("1950-06-26");

    assertThat(this.claim(this.mapping.toClaims(
        List.of(GenericAttribute.of(AttributeIdentifiers.CREDENTIAL_VALID_FROM, Instant.ofEpochSecond(1700000000L))),
        null), ClaimConstants.CREDENTIALS_VALID_FROM_CLAIM_NAME))
        .isEqualTo(1700000000L);
  }

  @Test
  void aMultiValuedAttributeGivesTheFirstValueToASingleValuedClaim() {
    assertThat(this.claim(this.mapping.toClaims(
        List.of(GenericAttribute.of(AttributeIdentifiers.EMAIL, List.of("a@example.com", "b@example.com"))), null),
        PersonClaims.EMAIL_CLAIM_NAME))
        .isEqualTo("a@example.com");
  }

  @Test
  void countryOfCitizenshipBecomesAnArray() {
    assertThat(this.claim(this.mapping.toClaims(
        List.of(GenericAttribute.of(AttributeIdentifiers.COUNTRY_OF_CITIZENSHIP, List.of("SE", "NO"))), null),
        PersonClaims.NATIONALITIES_CLAIM_NAME))
        .isEqualTo(List.of("SE", "NO"));
  }

  @Test
  void thePhoneNumberIsTheMobileNumberWhenThereIsOne() {
    final List<UserClaim> both = this.mapping.toClaims(List.of(
        GenericAttribute.of(AttributeIdentifiers.TELEPHONE_NUMBER, "+46890510"),
        GenericAttribute.of(AttributeIdentifiers.MOBILE_NUMBER, "+46703419886")), null);
    assertThat(this.claim(both, PersonClaims.PHONE_NUMBER_CLAIM_NAME)).isEqualTo("+46703419886");
    assertThat(this.claim(both, PersonClaims.MSISDN_CLAIM_NAME)).isEqualTo("+46703419886");

    final List<UserClaim> onlyTelephone = this.mapping.toClaims(
        List.of(GenericAttribute.of(AttributeIdentifiers.TELEPHONE_NUMBER, "+46890510")), null);
    assertThat(this.claim(onlyTelephone, PersonClaims.PHONE_NUMBER_CLAIM_NAME)).isEqualTo("+46890510");
    assertThat(this.claim(onlyTelephone, PersonClaims.MSISDN_CLAIM_NAME)).isNull();
  }

  @Test
  void theAddressPartsBecomeOneClaim() {
    final List<UserClaim> claims = this.mapping.toClaims(List.of(
        GenericAttribute.of(AttributeIdentifiers.STREET_ADDRESS, "Mosebacke torg 3"),
        GenericAttribute.of(AttributeIdentifiers.POST_OFFICE_BOX, "Box 1122"),
        GenericAttribute.of(AttributeIdentifiers.POSTAL_CODE, "11826"),
        GenericAttribute.of(AttributeIdentifiers.LOCALITY, "Stockholm"),
        GenericAttribute.of(AttributeIdentifiers.COUNTRY, "SE")), null);

    final Address address = (Address) this.claim(claims, PersonClaims.ADDRESS_CLAIM_NAME);
    assertThat(address).isNotNull();
    assertThat(address.getStreetAddress()).isEqualTo("Mosebacke torg 3\nBox 1122");
    assertThat(address.getPostalCode()).isEqualTo("11826");
    assertThat(address.getLocality()).isEqualTo("Stockholm");
    assertThat(address.getCountry()).isEqualTo("SE");
  }

  @Test
  void thePlaceOfBirthPartsBecomeOneClaim() {
    final JSONObject placeOfBirth = (JSONObject) this.claim(this.mapping.toClaims(List.of(
        GenericAttribute.of(AttributeIdentifiers.PLACE_OF_BIRTH_COUNTRY, "SE"),
        GenericAttribute.of(AttributeIdentifiers.PLACE_OF_BIRTH_LOCALITY, "Stockholm")), null),
        PersonClaims.PLACE_OF_BIRTH_CLAIM_NAME);

    assertThat(placeOfBirth).containsEntry("country", "SE").containsEntry("locality", "Stockholm");
  }

  @Test
  void aFreeTextPlaceOfBirthAloneBecomesTheLocality() {
    final JSONObject placeOfBirth = (JSONObject) this.claim(this.mapping.toClaims(
        List.of(GenericAttribute.of(AttributeIdentifiers.PLACE_OF_BIRTH, "Stockholm")), null),
        PersonClaims.PLACE_OF_BIRTH_CLAIM_NAME);

    assertThat(placeOfBirth).containsExactly(java.util.Map.entry("locality", "Stockholm"));
  }

  @Test
  void aFreeTextPlaceOfBirthIsNotUsedWhenThePartsAreKnown() {
    final JSONObject placeOfBirth = (JSONObject) this.claim(this.mapping.toClaims(List.of(
        GenericAttribute.of(AttributeIdentifiers.PLACE_OF_BIRTH, "Stockholm, SE"),
        GenericAttribute.of(AttributeIdentifiers.PLACE_OF_BIRTH_COUNTRY, "SE")), null),
        PersonClaims.PLACE_OF_BIRTH_CLAIM_NAME);

    assertThat(placeOfBirth).containsExactly(java.util.Map.entry("country", "SE"));
  }

  @Test
  void theGenderValueIsReleasedOnlyWhenItIsFemaleOrMale() {
    assertThat(this.claim(this.mapping.toClaims(
        List.of(GenericAttribute.of(AttributeIdentifiers.GENDER, "female")), null),
        PersonClaims.GENDER_CLAIM_NAME))
        .isEqualTo("female");
    assertThat(this.mapping.toClaims(
        List.of(GenericAttribute.of(AttributeIdentifiers.GENDER, "u")), null)).isEmpty();
  }

  @Test
  void attributesThatHaveNoClaimAreLeftOut() {
    assertThat(this.mapping.toClaims(List.of(
        GenericAttribute.of(AttributeIdentifiers.BIRTH_NAME, "Valfrid Danielsson"),
        GenericAttribute.of(AttributeIdentifiers.PREVIOUS_PERSONAL_IDENTITY_NUMBER, "195006262546"),
        GenericAttribute.of(AttributeIdentifiers.COUNTRY_OF_RESIDENCE, "SE"),
        GenericAttribute.of(AttributeIdentifiers.SAD, "sad-value"),
        GenericAttribute.of(AttributeIdentifiers.SIGN_MESSAGE_DIGEST, "digest"),
        GenericAttribute.of(AttributeIdentifiers.AUTH_CONTEXT_PARAMS, "params"),
        GenericAttribute.of(AttributeIdentifiers.EMPLOYEE_HSA_ID, "hsa"),
        GenericAttribute.of(AttributeIdentifiers.EIDAS_ADDRESS_POST_NAME, "London")), null))
        .isEmpty();
  }

  @Test
  void aBirthNamePartBecomesItsOwnClaim() {
    assertThat(this.claim(this.mapping.toClaims(
        List.of(GenericAttribute.of(AttributeIdentifiers.BIRTH_FAMILY_NAME, "Danielsson")), null),
        PersonClaims.BIRTH_FAMILY_NAME_CLAIM_NAME))
        .isEqualTo("Danielsson");
  }

  @Test
  void anApplicationCanReplaceABuiltInMapper() {
    this.mapping.getToProtocolMapping().register(new ToProtocolAttributeMapper<UserClaim>() {

      @Override
      public Collection<String> getSupportedIdentifiers() {
        return List.of(AttributeIdentifiers.SURNAME);
      }

      @Override
      public List<UserClaim> map(final List<GenericAttribute<? extends Serializable>> attributes,
          final ToProtocolMappingContext context) {
        return List.of(UserClaim.of("https://example.com/claim/surname",
            attributes.get(0).getStringValues().get(0)));
      }
    });

    final List<UserClaim> claims = this.mapping.toClaims(
        List.of(GenericAttribute.of(AttributeIdentifiers.SURNAME, "Lindeman")), null);
    assertThat(claims).singleElement().extracting(UserClaim::name).isEqualTo("https://example.com/claim/surname");
  }

  @Test
  void anApplicationCanAddAMapperForAnAttributeOfItsOwn() {
    this.mapping.getToProtocolMapping().register(
        new ClaimToProtocolMapper("attribute.employee-number", "https://example.com/claim/employeeNumber"));

    assertThat(this.claim(this.mapping.toClaims(
        List.of(GenericAttribute.of("attribute.employee-number", "4711")), null),
        "https://example.com/claim/employeeNumber"))
        .isEqualTo("4711");
  }

  @Test
  void aClaimProducedTwiceIsMerged() {
    assertThat(UserClaim.merge(
        UserClaim.of("x", new JSONObject(java.util.Map.of("a", "1"))),
        UserClaim.of("x", new JSONObject(java.util.Map.of("b", "2")))).value())
        .isEqualTo(new JSONObject(java.util.Map.of("a", "1", "b", "2")));

    assertThat(UserClaim.merge(UserClaim.of("x", "1"), UserClaim.of("x", "2")).value()).isEqualTo("1");
  }

}
