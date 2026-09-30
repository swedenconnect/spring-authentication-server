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
package se.swedenconnect.spring.authnserver.attributes.mapping;

import java.util.Collection;
import java.util.List;

import org.jspecify.annotations.NonNull;

import se.swedenconnect.spring.authnserver.attributes.GenericRequestedAttribute;

/**
 * Maps requested attributes from a protocol representation into the generic form.
 * <p>
 * A mapper declares the protocol names it handles, and is called once per mapping operation with the inputs carrying
 * those names. It may return any number of requested attributes, so one input may become several, and several inputs
 * may become one.
 * </p>
 * <p>
 * An input whose name no mapper declares is left out of the result. That is not an error.
 * </p>
 *
 * @param <I> the protocol representation of a requested attribute
 * @author Martin Lindström
 * @see ToProtocolAttributeMapper
 */
public interface FromProtocolAttributeMapper<I> {

  /**
   * Gets the protocol names that this mapper handles, for example SAML attribute names or OpenID Connect claim names.
   *
   * @return the protocol names
   */
  @NonNull Collection<String> getSupportedNames();

  /**
   * Maps the supplied inputs into generic requested attributes.
   *
   * @param inputs the inputs whose names this mapper declares, never empty
   * @param context the mapping context
   * @return the resulting requested attributes, possibly empty
   */
  @NonNull List<GenericRequestedAttribute> map(final @NonNull List<I> inputs,
      final @NonNull FromProtocolMappingContext<I> context);

}
