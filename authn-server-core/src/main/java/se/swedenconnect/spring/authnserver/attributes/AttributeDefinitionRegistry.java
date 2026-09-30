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
package se.swedenconnect.spring.authnserver.attributes;

import java.util.Collection;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * A registry of the generic attributes that are known to the application.
 * <p>
 * The library ships definitions for its built-in attributes, see {@link BuiltInAttributeDefinitions}. An application
 * that introduces attributes of its own registers definitions for them.
 * </p>
 *
 * @author Martin Lindström
 */
public interface AttributeDefinitionRegistry {

  /**
   * Gets the definition for the given attribute identifier.
   *
   * @param identifier the attribute identifier
   * @return the {@link AttributeDefinition}, or {@code null} if no definition has been registered
   */
  @Nullable AttributeDefinition getDefinition(final @NonNull String identifier);

  /**
   * Gets all registered definitions.
   *
   * @return all {@link AttributeDefinition}s
   */
  @NonNull Collection<AttributeDefinition> getDefinitions();

  /**
   * Registers a definition. A definition for an identifier that is already registered replaces the previous one.
   *
   * @param definition the definition to register
   */
  void register(final @NonNull AttributeDefinition definition);

}
