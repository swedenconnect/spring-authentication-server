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
import java.util.List;

import org.jspecify.annotations.NonNull;

import se.swedenconnect.spring.authnserver.attributes.GenericAttribute;
import se.swedenconnect.spring.authnserver.authentication.UserAuthentication;

/**
 * Decides which of the user's attributes are released to the requester.
 * <p>
 * A producer works on the generic attribute model. Mapping the released attributes to SAML attributes or OpenID
 * Connect claims is done afterwards by the protocol module, so a producer never sees protocol attributes.
 * </p>
 *
 * @author Martin Lindström
 * @see AttributeReleaseManager
 */
@FunctionalInterface
public interface AttributeProducer {

  /**
   * Decides which attributes to release.
   *
   * @param userAuthentication the authentication result
   * @return the released attributes, possibly empty
   */
  @NonNull List<GenericAttribute<? extends Serializable>> releaseAttributes(
      final @NonNull UserAuthentication userAuthentication);

}
