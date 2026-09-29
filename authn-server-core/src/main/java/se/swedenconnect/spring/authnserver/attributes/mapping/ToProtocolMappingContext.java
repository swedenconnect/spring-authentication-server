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
import jakarta.annotation.Nullable;

import java.io.Serializable;
import java.util.List;

import se.swedenconnect.spring.authnserver.attributes.AttributeDefinitionRegistry;
import se.swedenconnect.spring.authnserver.attributes.GenericAttribute;
import se.swedenconnect.spring.authnserver.attributes.GenericRequestedAttribute;

/**
 * The context handed to a {@link ToProtocolAttributeMapper}.
 * <p>
 * A mapper is given the attributes it declares that it handles, and this context, which holds the attribute
 * definitions, every attribute of the operation and the requested attributes. The requested attributes are what give
 * a mapper access to protocol data such as the delivery target of an OpenID Connect claim.
 * </p>
 *
 * @author Martin Lindström
 */
public interface ToProtocolMappingContext {

  /**
   * Gets the registry of known attribute definitions.
   *
   * @return an {@link AttributeDefinitionRegistry}
   */
  @Nonnull AttributeDefinitionRegistry getDefinitions();

  /**
   * Gets every attribute of the mapping operation, not only those handed to the mapper.
   *
   * @return all attributes of the operation
   */
  @Nonnull List<GenericAttribute<? extends Serializable>> getAllAttributes();

  /**
   * Gets the attribute having the supplied identifier.
   *
   * @param identifier the attribute identifier
   * @return the attribute, or {@code null} if it is not part of the operation
   */
  @Nullable GenericAttribute<? extends Serializable> getAttribute(final @Nonnull String identifier);

  /**
   * Gets the first string value of the attribute having the supplied identifier.
   *
   * @param identifier the attribute identifier
   * @return the value, or {@code null} if the attribute is not part of the operation
   */
  @Nullable String getStringValue(final @Nonnull String identifier);

  /**
   * Gets the requested attributes of the operation.
   *
   * @return the requested attributes, possibly empty
   */
  @Nonnull List<GenericRequestedAttribute> getRequestedAttributes();

  /**
   * Gets the requested attribute having the supplied identifier.
   *
   * @param identifier the attribute identifier
   * @return the requested attribute, or {@code null} if the attribute was not requested
   */
  @Nullable GenericRequestedAttribute getRequestedAttribute(final @Nonnull String identifier);

}
