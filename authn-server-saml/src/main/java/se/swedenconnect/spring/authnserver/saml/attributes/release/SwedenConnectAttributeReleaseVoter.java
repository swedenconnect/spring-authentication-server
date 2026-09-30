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

import java.io.Serializable;
import java.util.List;

import org.jspecify.annotations.NonNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import se.swedenconnect.opensaml.sweid.saml2.metadata.entitycategory.EntityCategoryConstants;
import se.swedenconnect.spring.authnserver.attributes.AttributeIdentifiers;
import se.swedenconnect.spring.authnserver.attributes.GenericAttribute;
import se.swedenconnect.spring.authnserver.attributes.release.AttributeReleaseVote;
import se.swedenconnect.spring.authnserver.attributes.release.AttributeReleaseVoter;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationRequirements;
import se.swedenconnect.spring.authnserver.authentication.UserAuthentication;
import se.swedenconnect.spring.authnserver.saml.authentication.SamlAuthenticationRequirements;

/**
 * An {@link AttributeReleaseVoter} applying the rules of the
 * <a href="https://docs.swedenconnect.se/technical-framework/">Technical Specifications for the Swedish eID
 * Framework</a>.
 * <p>
 * A Swedish coordination number ("samordningsnummer") is released only to a Service Provider that has declared the
 * {@code accepts-coordination-number} general entity category. Section 6.2 of
 * <a href="https://docs.swedenconnect.se/technical-framework/latest/06_-_Entity_Categories_for_the_Swedish_eID_Framework.html">Entity
 * Categories for the Swedish eID Framework</a> states that an Identity Provider must not deliver a coordination
 * number in the {@code personalIdentityNumber} attribute unless the Service Provider has opted in.
 * </p>
 * <p>
 * The rule covers {@link AttributeIdentifiers#COORDINATION_NUMBER} only. The same section says that it does not apply
 * to {@code mappedPersonalIdentityNumber}, so {@link AttributeIdentifiers#MAPPED_COORDINATION_NUMBER} is released
 * whether the Service Provider has opted in or not.
 * </p>
 * <p>
 * Nothing else is decided here. A personal identity number, and every other attribute, is left to the other voters.
 * </p>
 *
 * @author Martin Lindström
 */
public class SwedenConnectAttributeReleaseVoter implements AttributeReleaseVoter {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(SwedenConnectAttributeReleaseVoter.class);

  /** The entity category that a Service Provider declares to accept coordination numbers. */
  private static final String ACCEPTS_COORDINATION_NUMBER =
      EntityCategoryConstants.GENERAL_CATEGORY_ACCEPTS_COORDINATION_NUMBER.getUri();

  /** {@inheritDoc} */
  @Override
  public @NonNull AttributeReleaseVote vote(final @NonNull UserAuthentication userAuthentication,
      final @NonNull GenericAttribute<? extends Serializable> attribute) {

    if (AttributeIdentifiers.COORDINATION_NUMBER.equals(attribute.getIdentifier())
        && !entityCategories(userAuthentication).contains(ACCEPTS_COORDINATION_NUMBER)) {
      log.info("Attribute '{}' will not be released since it is a coordination number and the SP has not opted-in"
              + " ({} not declared) [{}]",
          attribute.getIdentifier(), ACCEPTS_COORDINATION_NUMBER, userAuthentication.getLogString());
      return AttributeReleaseVote.DONT_INCLUDE;
    }
    return AttributeReleaseVote.DONT_KNOW;
  }

  /**
   * Gets the entity categories that the Service Provider declares.
   *
   * @param userAuthentication the authentication result
   * @return the declared entity categories, possibly empty
   */
  private static @NonNull List<String> entityCategories(final @NonNull UserAuthentication userAuthentication) {
    final AuthenticationRequirements requirements = userAuthentication.getAuthnRequirements();
    return requirements instanceof final SamlAuthenticationRequirements samlRequirements
        ? samlRequirements.getEntityCategories()
        : List.of();
  }

}
