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
import java.util.ArrayList;
import java.util.List;

import org.jspecify.annotations.NonNull;

import se.swedenconnect.spring.authnserver.attributes.GenericAttribute;
import se.swedenconnect.spring.authnserver.attributes.GenericRequestedAttribute;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationRequirements;
import se.swedenconnect.spring.authnserver.authentication.UserAuthentication;
import se.swedenconnect.spring.authnserver.error.CommonUnrecoverableError;
import se.swedenconnect.spring.authnserver.error.UnrecoverableErrorException;

/**
 * The default {@link AttributeProducer}, releasing the user attributes that the requester asked for.
 * <p>
 * What the requester asked for is the requested attributes of the authentication requirements, which hold both what
 * the request stated and what it asked for implicitly, such as through SAML entity categories or OpenID Connect
 * scopes.
 * </p>
 * <p>
 * The requirements are those of the request being answered. When a previous authentication is reused for single
 * sign-on, the attributes released are therefore the ones the new request asked for, not the ones the original
 * request asked for.
 * </p>
 *
 * @author Martin Lindström
 */
public class DefaultAttributeProducer implements AttributeProducer {

  /**
   * Releases the user attributes that are among the requested attributes of the authentication requirements.
   *
   * @throws UnrecoverableErrorException if the result carries no authentication requirements
   */
  @Override
  public @NonNull List<GenericAttribute<? extends Serializable>> releaseAttributes(
      final @NonNull UserAuthentication userAuthentication) {

    final AuthenticationRequirements requirements = userAuthentication.getAuthnRequirements();
    if (requirements == null) {
      throw new UnrecoverableErrorException(CommonUnrecoverableError.INTERNAL,
          "No authentication requirements available");
    }
    final List<String> requested = requirements.getRequestedAttributes().stream()
        .map(GenericRequestedAttribute::getIdentifier)
        .toList();

    final List<GenericAttribute<? extends Serializable>> released = new ArrayList<>();
    for (final GenericAttribute<?> attribute : userAuthentication.getAuthenticatedUser().getAttributes()) {
      if (requested.contains(attribute.getIdentifier())) {
        released.add(attribute);
      }
    }
    return released;
  }

}
