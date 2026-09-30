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
package se.swedenconnect.spring.authnserver.saml.attributes.requested;

import java.util.List;

import org.jspecify.annotations.NonNull;

import se.swedenconnect.spring.authnserver.saml.attributes.SamlRequestedAttribute;

/**
 * Finds the attributes that a SAML requester asks for, from one source.
 * <p>
 * A Service Provider states what it needs in more than one place, and each place has a processor of its own. See
 * {@link SamlRequestedAttributeResolver}, which runs them all and gives the result in the protocol-neutral form.
 * </p>
 *
 * @author Martin Lindström
 * @see SamlRequestedAttributeResolver
 */
public interface RequestedAttributeProcessor {

  /**
   * Finds the requested attributes of this processor's source.
   *
   * @param context the authentication request and the metadata of the Service Provider that sent it
   * @return the requested attributes, possibly empty
   */
  @NonNull List<SamlRequestedAttribute> extractRequestedAttributes(final @NonNull RequestedAttributeContext context);

}
