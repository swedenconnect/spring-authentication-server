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
package se.swedenconnect.spring.authnserver.attributes.release;

import java.io.Serializable;
import java.util.Arrays;
import java.util.List;

import se.swedenconnect.spring.authnserver.AuthenticationTestSupport;
import se.swedenconnect.spring.authnserver.attributes.GenericAttribute;
import se.swedenconnect.spring.authnserver.attributes.GenericRequestedAttribute;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationRequirements;
import se.swedenconnect.spring.authnserver.authentication.Requester;
import se.swedenconnect.spring.authnserver.authentication.UserAuthentication;

/**
 * Fixtures for the tests of the attribute release.
 *
 * @author Martin Lindström
 */
final class AttributeReleaseTestSupport {

  /** The Service Provider of the tests. */
  static final Requester SP = AuthenticationTestSupport.samlRequester("https://sp.example.com/sp");

  /**
   * Creates an authentication result for a user that has been asked for the supplied attributes.
   *
   * @param requestedAttributes the identifiers of the requested attributes
   * @return a {@link UserAuthentication}
   */
  static UserAuthentication authentication(final String... requestedAttributes) {
    final UserAuthentication authentication = AuthenticationTestSupport.authentication(
        AuthenticationTestSupport.user(), SP, List.of(requestedAttributes));
    authentication.setAuthnRequirements(requirements(requestedAttributes));
    return authentication;
  }

  /**
   * Creates requirements asking for the supplied attributes.
   *
   * @param requestedAttributes the identifiers of the requested attributes
   * @return an {@link AuthenticationRequirements}
   */
  static AuthenticationRequirements requirements(final String... requestedAttributes) {
    final AuthenticationRequirements requirements = new AuthenticationRequirements();
    requirements.setRequestedAttributes(
        Arrays.stream(requestedAttributes).map(GenericRequestedAttribute::of).toList());
    return requirements;
  }

  /**
   * Gets the identifiers of the supplied attributes.
   *
   * @param attributes the attributes
   * @return the attribute identifiers
   */
  static List<String> identifiers(final List<GenericAttribute<? extends Serializable>> attributes) {
    return attributes.stream().map(GenericAttribute::getIdentifier).toList();
  }

  /**
   * Creates a producer releasing the supplied attributes.
   *
   * @param attributes the attributes to release
   * @return an {@link AttributeProducer}
   */
  @SafeVarargs
  static AttributeProducer producer(final GenericAttribute<? extends Serializable>... attributes) {
    return authentication -> List.of(attributes);
  }

  // Hidden constructor
  private AttributeReleaseTestSupport() {
  }

}
