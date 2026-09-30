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

import java.io.Serializable;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.BinaryOperator;
import java.util.function.Function;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import se.swedenconnect.spring.authnserver.attributes.AttributeDefinitionRegistry;
import se.swedenconnect.spring.authnserver.attributes.GenericAttribute;
import se.swedenconnect.spring.authnserver.attributes.GenericRequestedAttribute;

/**
 * Holds the {@link ToProtocolAttributeMapper}s of a protocol and performs the mapping of attributes from the generic
 * form into the protocol representation.
 * <p>
 * Registering a mapper for a generic attribute identifier that another mapper already handles replaces that mapper for
 * that identifier. This is how an application replaces a built-in mapping with one of its own.
 * </p>
 * <p>
 * Should two mappers produce protocol attributes with the same name, the results are merged using the merge function
 * given to the constructor.
 * </p>
 *
 * @param <O> the protocol representation of an attribute
 * @author Martin Lindström
 */
public class ToProtocolAttributeMapping<O> {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(ToProtocolAttributeMapping.class);

  /** The attribute definitions. */
  private final AttributeDefinitionRegistry definitions;

  /** Extracts the protocol name from an output. */
  private final Function<O, String> nameExtractor;

  /** Merges two outputs having the same protocol name. */
  private final BinaryOperator<O> merger;

  /** The mappers, keyed by the generic attribute identifiers they handle. */
  private final Map<String, ToProtocolAttributeMapper<O>> mappers = new LinkedHashMap<>();

  /**
   * Constructor.
   *
   * @param definitions the attribute definitions
   * @param nameExtractor a function giving the protocol name of an output
   * @param merger a function merging two outputs having the same protocol name
   */
  public ToProtocolAttributeMapping(final @NonNull AttributeDefinitionRegistry definitions,
      final @NonNull Function<O, String> nameExtractor, final @NonNull BinaryOperator<O> merger) {
    this.definitions = Objects.requireNonNull(definitions, "definitions must not be null");
    this.nameExtractor = Objects.requireNonNull(nameExtractor, "nameExtractor must not be null");
    this.merger = Objects.requireNonNull(merger, "merger must not be null");
  }

  /**
   * Registers a mapper. It takes over every generic attribute identifier it declares.
   *
   * @param mapper the mapper to register
   */
  public void register(final @NonNull ToProtocolAttributeMapper<O> mapper) {
    Objects.requireNonNull(mapper, "mapper must not be null");
    for (final String identifier : mapper.getSupportedIdentifiers()) {
      final ToProtocolAttributeMapper<O> previous = this.mappers.put(identifier, mapper);
      if (previous != null && previous != mapper) {
        log.debug("Mapper {} replaced {} for attribute '{}'",
            mapper.getClass().getSimpleName(), previous.getClass().getSimpleName(), identifier);
      }
    }
  }

  /**
   * Registers several mappers.
   *
   * @param mappers the mappers to register
   */
  public void registerAll(final @NonNull List<? extends ToProtocolAttributeMapper<O>> mappers) {
    Objects.requireNonNull(mappers, "mappers must not be null").forEach(this::register);
  }

  /**
   * Gets the mapper that handles an attribute.
   *
   * @param identifier the attribute identifier
   * @return the mapper, or {@code null} if no mapper handles the attribute
   */
  public @Nullable ToProtocolAttributeMapper<O> getMapper(final @NonNull String identifier) {
    return this.mappers.get(Objects.requireNonNull(identifier, "identifier must not be null"));
  }

  /**
   * Maps the supplied attributes into the protocol representation. Attributes that no mapper handles are left out.
   *
   * @param attributes the attributes to map
   * @param requestedAttributes the requested attributes of the operation, may be {@code null}
   * @return the protocol attributes
   */
  public @NonNull List<O> map(final @NonNull List<GenericAttribute<? extends Serializable>> attributes,
      final @Nullable List<GenericRequestedAttribute> requestedAttributes) {
    Objects.requireNonNull(attributes, "attributes must not be null");
    final ToProtocolMappingContext context = new Context(this.definitions, attributes,
        requestedAttributes != null ? requestedAttributes : List.of());

    final Map<String, O> result = new LinkedHashMap<>();
    for (final ToProtocolAttributeMapper<O> mapper : new LinkedHashSet<>(this.mappers.values())) {
      final List<GenericAttribute<? extends Serializable>> handled = new ArrayList<>();
      for (final GenericAttribute<? extends Serializable> attribute : attributes) {
        if (this.mappers.get(attribute.getIdentifier()) == mapper) {
          handled.add(attribute);
        }
      }
      if (handled.isEmpty()) {
        continue;
      }
      for (final O output : mapper.map(handled, context)) {
        final String name = this.nameExtractor.apply(output);
        result.merge(name, output, this.merger);
      }
    }
    if (log.isTraceEnabled()) {
      for (final GenericAttribute<? extends Serializable> attribute : attributes) {
        if (!this.mappers.containsKey(attribute.getIdentifier())) {
          log.trace("No mapper handles '{}' - attribute is left out", attribute.getIdentifier());
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
  public @NonNull AttributeDefinitionRegistry getDefinitions() {
    return this.definitions;
  }

  /**
   * The {@link ToProtocolMappingContext} implementation.
   */
  private static class Context implements ToProtocolMappingContext {

    /** The attribute definitions. */
    private final AttributeDefinitionRegistry definitions;

    /** All attributes of the operation. */
    private final List<GenericAttribute<? extends Serializable>> attributes;

    /** The requested attributes of the operation. */
    private final List<GenericRequestedAttribute> requestedAttributes;

    /**
     * Constructor.
     *
     * @param definitions the attribute definitions
     * @param attributes all attributes of the operation
     * @param requestedAttributes the requested attributes of the operation
     */
    Context(final AttributeDefinitionRegistry definitions,
        final List<GenericAttribute<? extends Serializable>> attributes,
        final List<GenericRequestedAttribute> requestedAttributes) {
      this.definitions = definitions;
      this.attributes = attributes;
      this.requestedAttributes = requestedAttributes;
    }

    /** {@inheritDoc} */
    @Override
    public @NonNull AttributeDefinitionRegistry getDefinitions() {
      return this.definitions;
    }

    /** {@inheritDoc} */
    @Override
    public @NonNull List<GenericAttribute<? extends Serializable>> getAllAttributes() {
      return this.attributes;
    }

    /** {@inheritDoc} */
    @Override
    public @Nullable GenericAttribute<? extends Serializable> getAttribute(final @NonNull String identifier) {
      return this.attributes.stream()
          .filter(a -> a.getIdentifier().equals(identifier))
          .findFirst()
          .orElse(null);
    }

    /** {@inheritDoc} */
    @Override
    public @Nullable String getStringValue(final @NonNull String identifier) {
      final GenericAttribute<? extends Serializable> attribute = this.getAttribute(identifier);
      return attribute != null ? String.valueOf(attribute.getValue()) : null;
    }

    /** {@inheritDoc} */
    @Override
    public @NonNull List<GenericRequestedAttribute> getRequestedAttributes() {
      return this.requestedAttributes;
    }

    /** {@inheritDoc} */
    @Override
    public @Nullable GenericRequestedAttribute getRequestedAttribute(final @NonNull String identifier) {
      return this.requestedAttributes.stream()
          .filter(a -> a.getIdentifier().equals(identifier))
          .findFirst()
          .orElse(null);
    }

  }

}
