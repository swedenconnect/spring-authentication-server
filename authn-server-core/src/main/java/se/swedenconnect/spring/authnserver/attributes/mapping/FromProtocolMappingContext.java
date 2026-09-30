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

import java.util.List;

import org.jspecify.annotations.NonNull;

import se.swedenconnect.spring.authnserver.attributes.AttributeDefinitionRegistry;

/**
 * The context handed to a {@link FromProtocolAttributeMapper}.
 * <p>
 * A mapper is given the inputs it declares that it handles, and this context, which holds the attribute definitions
 * and every input of the operation. The latter is what makes it possible for a mapper to let its result depend on
 * what else was requested.
 * </p>
 *
 * @param <I> the protocol representation of a requested attribute
 * @author Martin Lindström
 */
public interface FromProtocolMappingContext<I> {

  /**
   * Gets the registry of known attribute definitions.
   *
   * @return an {@link AttributeDefinitionRegistry}
   */
  @NonNull AttributeDefinitionRegistry getDefinitions();

  /**
   * Gets every input of the mapping operation, not only those handed to the mapper.
   *
   * @return all inputs of the operation
   */
  @NonNull List<I> getAllInputs();

}
