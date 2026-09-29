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

import static org.assertj.core.api.Assertions.assertThat;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * Tests for {@link BuiltInAttributeDefinitions}.
 *
 * @author Martin Lindström
 */
class BuiltInAttributeDefinitionsTest {

  @Test
  void everyIdentifierHasADefinition() throws Exception {
    final List<String> identifiers = new ArrayList<>();
    for (final Field field : AttributeIdentifiers.class.getDeclaredFields()) {
      if (Modifier.isStatic(field.getModifiers()) && field.getType() == String.class
          && !"PREFIX".equals(field.getName())) {
        identifiers.add((String) field.get(null));
      }
    }
    assertThat(identifiers).isNotEmpty();

    final List<String> defined = BuiltInAttributeDefinitions.getDefinitions().stream()
        .map(AttributeDefinition::identifier)
        .toList();
    assertThat(defined).containsExactlyInAnyOrderElementsOf(identifiers);
  }

  @Test
  void allIdentifiersUseThePrefixAndKebabCase() {
    for (final AttributeDefinition definition : BuiltInAttributeDefinitions.getDefinitions()) {
      assertThat(definition.identifier()).startsWith(AttributeIdentifiers.PREFIX);
      final String name = definition.identifier().substring(AttributeIdentifiers.PREFIX.length());
      assertThat(name).matches("[a-z0-9]+(-[a-z0-9]+)*");
    }
  }

  @Test
  void definitionsAreUnique() {
    final List<String> identifiers = BuiltInAttributeDefinitions.getDefinitions().stream()
        .map(AttributeDefinition::identifier)
        .toList();
    assertThat(identifiers).doesNotHaveDuplicates();
  }

  @Test
  void registryHoldsTheBuiltInDefinitions() {
    final AttributeDefinitionRegistry registry = new DefaultAttributeDefinitionRegistry();
    assertThat(registry.getDefinitions()).hasSameSizeAs(BuiltInAttributeDefinitions.getDefinitions());
    assertThat(registry.getDefinition(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER)).isNotNull();
    assertThat(registry.getDefinition("attribute.no-such-attribute")).isNull();
  }

  @Test
  void anApplicationCanAddAndReplaceDefinitions() {
    final AttributeDefinitionRegistry registry = new DefaultAttributeDefinitionRegistry();
    final int size = registry.getDefinitions().size();

    registry.register(AttributeDefinition.ofString("attribute.employee-number", "Employee number."));
    assertThat(registry.getDefinitions()).hasSize(size + 1);
    assertThat(registry.getDefinition("attribute.employee-number")).isNotNull();

    registry.register(new AttributeDefinition(AttributeIdentifiers.LOCALE, String.class, true, "Locales."));
    assertThat(registry.getDefinitions()).hasSize(size + 1);
    assertThat(registry.getDefinition(AttributeIdentifiers.LOCALE).multiValued()).isTrue();
  }

}
