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

import jakarta.annotation.Nonnull;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import se.swedenconnect.spring.authnserver.attributes.AttributeDefinitionRegistry;
import se.swedenconnect.spring.authnserver.attributes.GenericRequestedAttribute;

/**
 * Holds the {@link FromProtocolAttributeMapper}s of a protocol and performs the mapping of requested attributes into
 * the generic form.
 * <p>
 * Registering a mapper for a protocol name that another mapper already handles replaces that mapper for that name.
 * This is how an application replaces a built-in mapping with one of its own.
 * </p>
 * <p>
 * Should two mappers produce requested attributes with the same identifier, the results are merged. The attribute is
 * then essential if any of them said so.
 * </p>
 *
 * @param <I> the protocol representation of a requested attribute
 * @author Martin Lindström
 */
public class FromProtocolAttributeMapping<I> {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(FromProtocolAttributeMapping.class);

  /** The attribute definitions. */
  private final AttributeDefinitionRegistry definitions;

  /** Extracts the protocol name from an input. */
  private final Function<I, String> nameExtractor;

  /** The mappers, keyed by the protocol names they handle. */
  private final Map<String, FromProtocolAttributeMapper<I>> mappers = new LinkedHashMap<>();

  /**
   * Constructor.
   *
   * @param definitions the attribute definitions
   * @param nameExtractor a function giving the protocol name of an input
   */
  public FromProtocolAttributeMapping(final @Nonnull AttributeDefinitionRegistry definitions,
      final @Nonnull Function<I, String> nameExtractor) {
    this.definitions = Objects.requireNonNull(definitions, "definitions must not be null");
    this.nameExtractor = Objects.requireNonNull(nameExtractor, "nameExtractor must not be null");
  }

  /**
   * Registers a mapper. It takes over every protocol name it declares.
   *
   * @param mapper the mapper to register
   */
  public void register(final @Nonnull FromProtocolAttributeMapper<I> mapper) {
    Objects.requireNonNull(mapper, "mapper must not be null");
    for (final String name : mapper.getSupportedNames()) {
      final FromProtocolAttributeMapper<I> previous = this.mappers.put(name, mapper);
      if (previous != null && previous != mapper) {
        log.debug("Mapper {} replaced {} for protocol name '{}'",
            mapper.getClass().getSimpleName(), previous.getClass().getSimpleName(), name);
      }
    }
  }

  /**
   * Registers several mappers.
   *
   * @param mappers the mappers to register
   */
  public void registerAll(final @Nonnull List<? extends FromProtocolAttributeMapper<I>> mappers) {
    Objects.requireNonNull(mappers, "mappers must not be null").forEach(this::register);
  }

  /**
   * Maps the supplied protocol requested attributes into the generic form. Inputs that no mapper handles are left out.
   *
   * @param inputs the protocol requested attributes
   * @return the generic requested attributes
   */
  public @Nonnull List<GenericRequestedAttribute> map(final @Nonnull List<I> inputs) {
    Objects.requireNonNull(inputs, "inputs must not be null");
    final FromProtocolMappingContext<I> context = new Context(this.definitions, inputs);

    final Map<String, GenericRequestedAttribute> result = new LinkedHashMap<>();
    for (final FromProtocolAttributeMapper<I> mapper : new LinkedHashSet<>(this.mappers.values())) {
      final List<I> handled = new ArrayList<>();
      for (final I input : inputs) {
        final String name = this.nameExtractor.apply(input);
        if (name != null && this.mappers.get(name) == mapper) {
          handled.add(input);
        }
      }
      if (handled.isEmpty()) {
        continue;
      }
      for (final GenericRequestedAttribute requested : mapper.map(handled, context)) {
        result.merge(requested.getIdentifier(), requested, GenericRequestedAttribute::merge);
      }
    }
    if (log.isTraceEnabled()) {
      for (final I input : inputs) {
        final String name = this.nameExtractor.apply(input);
        if (name == null || !this.mappers.containsKey(name)) {
          log.trace("No mapper handles '{}' - requested attribute is left out", name);
        }
      }
    }
    return List.copyOf(result.values());
  }

  /**
   * Gets the attribute definitions that this mapping uses.
   *
   * @return an {@link AttributeDefinitionRegistry}
   */
  public @Nonnull AttributeDefinitionRegistry getDefinitions() {
    return this.definitions;
  }

  /**
   * The {@link FromProtocolMappingContext} implementation.
   *
   * @param definitions the attribute definitions
   * @param allInputs all inputs of the operation
   */
  private record Context<I>(AttributeDefinitionRegistry definitions, List<I> allInputs)
      implements FromProtocolMappingContext<I> {

    /** {@inheritDoc} */
    @Override
    public @Nonnull AttributeDefinitionRegistry getDefinitions() {
      return this.definitions;
    }

    /** {@inheritDoc} */
    @Override
    public @Nonnull List<I> getAllInputs() {
      return this.allInputs;
    }
  }

}
