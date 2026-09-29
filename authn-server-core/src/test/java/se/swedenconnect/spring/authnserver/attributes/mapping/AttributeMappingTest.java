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

import static org.assertj.core.api.Assertions.assertThat;

import java.io.Serializable;
import java.util.Collection;
import java.util.List;

import org.junit.jupiter.api.Test;

import se.swedenconnect.spring.authnserver.attributes.AttributeDefinition;
import se.swedenconnect.spring.authnserver.attributes.AttributeDefinitionRegistry;
import se.swedenconnect.spring.authnserver.attributes.DefaultAttributeDefinitionRegistry;
import se.swedenconnect.spring.authnserver.attributes.GenericAttribute;
import se.swedenconnect.spring.authnserver.attributes.GenericRequestedAttribute;

/**
 * Tests for {@link FromProtocolAttributeMapping} and {@link ToProtocolAttributeMapping} using a protocol where an
 * attribute is a name and a list of values.
 *
 * @author Martin Lindström
 */
class AttributeMappingTest {

  /** A protocol attribute. */
  private record ProtocolAttribute(String name, List<String> values) {
  }

  private static final String A = "attribute.a";
  private static final String B = "attribute.b";
  private static final String C = "attribute.c";

  private static AttributeDefinitionRegistry definitions() {
    final AttributeDefinitionRegistry registry = new DefaultAttributeDefinitionRegistry(List.of(
        AttributeDefinition.ofString(A, "A."),
        AttributeDefinition.ofString(B, "B."),
        AttributeDefinition.ofString(C, "C.")));
    return registry;
  }

  private static FromProtocolAttributeMapping<ProtocolAttribute> fromMapping() {
    return new FromProtocolAttributeMapping<>(definitions(), ProtocolAttribute::name);
  }

  private static ToProtocolAttributeMapping<ProtocolAttribute> toMapping() {
    return new ToProtocolAttributeMapping<>(definitions(), ProtocolAttribute::name,
        (first, second) -> new ProtocolAttribute(first.name(),
            java.util.stream.Stream.concat(first.values().stream(), second.values().stream()).distinct().toList()));
  }

  /** Maps one protocol name into the supplied identifiers. */
  private record FromMapper(String name, List<String> identifiers)
      implements FromProtocolAttributeMapper<ProtocolAttribute> {

    @Override
    public Collection<String> getSupportedNames() {
      return List.of(this.name);
    }

    @Override
    public List<GenericRequestedAttribute> map(final List<ProtocolAttribute> inputs,
        final FromProtocolMappingContext<ProtocolAttribute> context) {
      return this.identifiers.stream()
          .map(i -> new GenericRequestedAttribute(i, true, inputs.get(0).values(), null))
          .toList();
    }
  }

  /** Maps the supplied identifiers into one protocol attribute holding all their values. */
  private record ToMapper(String name, List<String> identifiers)
      implements ToProtocolAttributeMapper<ProtocolAttribute> {

    @Override
    public Collection<String> getSupportedIdentifiers() {
      return this.identifiers;
    }

    @Override
    public List<ProtocolAttribute> map(final List<GenericAttribute<? extends Serializable>> attributes,
        final ToProtocolMappingContext context) {
      return List.of(new ProtocolAttribute(this.name,
          attributes.stream().flatMap(a -> a.getStringValues().stream()).toList()));
    }
  }

  @Test
  void oneInputBecomesSeveralRequestedAttributes() {
    final FromProtocolAttributeMapping<ProtocolAttribute> mapping = fromMapping();
    mapping.register(new FromMapper("x", List.of(A, B)));

    final List<GenericRequestedAttribute> result = mapping.map(List.of(new ProtocolAttribute("x", List.of())));
    assertThat(result).extracting(GenericRequestedAttribute::getIdentifier).containsExactly(A, B);
    assertThat(result).allMatch(GenericRequestedAttribute::isEssential);
  }

  @Test
  void requestedValuesAreCarriedOver() {
    final FromProtocolAttributeMapping<ProtocolAttribute> mapping = fromMapping();
    mapping.register(new FromMapper("x", List.of(A)));

    final List<GenericRequestedAttribute> result =
        mapping.map(List.of(new ProtocolAttribute("x", List.of("one", "two"))));
    assertThat(result).singleElement()
        .extracting(GenericRequestedAttribute::getRequestedValues)
        .isEqualTo(List.of("one", "two"));
  }

  @Test
  void anInputThatNoMapperHandlesIsLeftOut() {
    final FromProtocolAttributeMapping<ProtocolAttribute> mapping = fromMapping();
    mapping.register(new FromMapper("x", List.of(A)));

    final List<GenericRequestedAttribute> result = mapping.map(List.of(
        new ProtocolAttribute("x", List.of()), new ProtocolAttribute("unknown", List.of())));
    assertThat(result).extracting(GenericRequestedAttribute::getIdentifier).containsExactly(A);
  }

  @Test
  void noInputAtAllGivesNoResult() {
    final FromProtocolAttributeMapping<ProtocolAttribute> mapping = fromMapping();
    mapping.register(new FromMapper("x", List.of(A)));
    assertThat(mapping.map(List.of())).isEmpty();
  }

  @Test
  void requestedAttributesProducedTwiceAreMerged() {
    final FromProtocolAttributeMapping<ProtocolAttribute> mapping = fromMapping();
    mapping.register(new FromMapper("x", List.of(A)));
    mapping.register(new FromMapper("y", List.of(A)));

    final List<GenericRequestedAttribute> result = mapping.map(List.of(
        new ProtocolAttribute("x", List.of()), new ProtocolAttribute("y", List.of())));
    assertThat(result).singleElement().extracting(GenericRequestedAttribute::getIdentifier).isEqualTo(A);
  }

  @Test
  void aRegisteredMapperReplacesTheOneThatHeldTheName() {
    final FromProtocolAttributeMapping<ProtocolAttribute> mapping = fromMapping();
    mapping.register(new FromMapper("x", List.of(A)));
    mapping.register(new FromMapper("x", List.of(C)));

    final List<GenericRequestedAttribute> result = mapping.map(List.of(new ProtocolAttribute("x", List.of())));
    assertThat(result).extracting(GenericRequestedAttribute::getIdentifier).containsExactly(C);
  }

  @Test
  void severalAttributesBecomeOneProtocolAttribute() {
    final ToProtocolAttributeMapping<ProtocolAttribute> mapping = toMapping();
    mapping.register(new ToMapper("x", List.of(A, B)));

    final List<ProtocolAttribute> result = mapping.map(
        List.of(GenericAttribute.of(A, "1"), GenericAttribute.of(B, "2")), null);
    assertThat(result).singleElement().isEqualTo(new ProtocolAttribute("x", List.of("1", "2")));
  }

  @Test
  void anAttributeThatNoMapperHandlesIsLeftOut() {
    final ToProtocolAttributeMapping<ProtocolAttribute> mapping = toMapping();
    mapping.register(new ToMapper("x", List.of(A)));

    final List<ProtocolAttribute> result = mapping.map(
        List.of(GenericAttribute.of(A, "1"), GenericAttribute.of(C, "3")), null);
    assertThat(result).singleElement().isEqualTo(new ProtocolAttribute("x", List.of("1")));
  }

  @Test
  void protocolAttributesWithTheSameNameAreMerged() {
    final ToProtocolAttributeMapping<ProtocolAttribute> mapping = toMapping();
    mapping.register(new ToMapper("x", List.of(A)));
    mapping.register(new ToMapper("x", List.of(B)));

    final List<ProtocolAttribute> result = mapping.map(
        List.of(GenericAttribute.of(A, "1"), GenericAttribute.of(B, "2")), null);
    assertThat(result).singleElement().isEqualTo(new ProtocolAttribute("x", List.of("1", "2")));
  }

  @Test
  void theMapperSeesEveryAttributeAndTheRequestedAttributes() {
    final ToProtocolAttributeMapping<ProtocolAttribute> mapping = toMapping();
    mapping.register(new ToProtocolAttributeMapper<ProtocolAttribute>() {

      @Override
      public Collection<String> getSupportedIdentifiers() {
        return List.of(A);
      }

      @Override
      public List<ProtocolAttribute> map(final List<GenericAttribute<? extends Serializable>> attributes,
          final ToProtocolMappingContext context) {
        assertThat(context.getAllAttributes()).hasSize(2);
        assertThat(context.getStringValue(C)).isEqualTo("3");
        assertThat(context.getAttribute("attribute.missing")).isNull();
        assertThat(context.getRequestedAttribute(A)).isNotNull();
        assertThat(context.getRequestedAttribute(B)).isNull();
        assertThat(context.getDefinitions().getDefinition(A)).isNotNull();
        return List.of(new ProtocolAttribute("x", List.of(context.getStringValue(C))));
      }
    });

    final List<ProtocolAttribute> result = mapping.map(
        List.of(GenericAttribute.of(A, "1"), GenericAttribute.of(C, "3")),
        List.of(GenericRequestedAttribute.of(A, true)));
    assertThat(result).singleElement().isEqualTo(new ProtocolAttribute("x", List.of("3")));
  }

}
