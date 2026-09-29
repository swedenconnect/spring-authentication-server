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

import jakarta.annotation.Nonnull;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import se.swedenconnect.spring.authnserver.attributes.GenericAttribute;
import se.swedenconnect.spring.authnserver.authentication.UserAuthentication;

/**
 * An {@link AttributeProducer} releasing every attribute of the authenticated user, whether it was asked for or not.
 * <p>
 * Use it where the requester is to receive everything the server knows, and leave the filtering to the
 * {@link AttributeReleaseVoter}s.
 * </p>
 *
 * @author Martin Lindström
 */
public class ReleaseAllAttributeProducer implements AttributeProducer {

  /**
   * Releases every attribute of the authenticated user.
   */
  @Override
  public @Nonnull List<GenericAttribute<? extends Serializable>> releaseAttributes(
      final @Nonnull UserAuthentication userAuthentication) {
    return new ArrayList<>(userAuthentication.getAuthenticatedUser().getAttributes());
  }

}
