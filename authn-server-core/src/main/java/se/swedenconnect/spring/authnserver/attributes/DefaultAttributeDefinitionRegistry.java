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
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * The default {@link AttributeDefinitionRegistry}. Unless told otherwise it starts out holding the definitions for
 * the library's built-in attributes.
 *
 * @author Martin Lindström
 */
public class DefaultAttributeDefinitionRegistry implements AttributeDefinitionRegistry {

  /** The registered definitions. */
  private final Map<String, AttributeDefinition> definitions = new LinkedHashMap<>();

  /**
   * Default constructor creating a registry holding the built-in attribute definitions.
   */
  public DefaultAttributeDefinitionRegistry() {
    this(BuiltInAttributeDefinitions.getDefinitions());
  }

  /**
   * Constructor creating a registry holding the supplied definitions.
   *
   * @param definitions the definitions to register
   */
  public DefaultAttributeDefinitionRegistry(final @NonNull List<AttributeDefinition> definitions) {
    Objects.requireNonNull(definitions, "definitions must not be null").forEach(this::register);
  }

  /** {@inheritDoc} */
  @Override
  public @Nullable AttributeDefinition getDefinition(final @NonNull String identifier) {
    return this.definitions.get(Objects.requireNonNull(identifier, "identifier must not be null"));
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull Collection<AttributeDefinition> getDefinitions() {
    return Collections.unmodifiableCollection(this.definitions.values());
  }

  /** {@inheritDoc} */
  @Override
  public void register(final @NonNull AttributeDefinition definition) {
    Objects.requireNonNull(definition, "definition must not be null");
    this.definitions.put(definition.identifier(), definition);
  }

}
