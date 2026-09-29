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

import java.io.Serializable;
import java.util.Collection;
import java.util.List;

import se.swedenconnect.spring.authnserver.attributes.GenericAttribute;

/**
 * Maps attributes from the generic form into a protocol representation.
 * <p>
 * A mapper declares the generic attribute identifiers it handles, and is called once per mapping operation with the
 * attributes carrying those identifiers. It may return any number of protocol attributes, so one attribute may become
 * several, several attributes may become one, and the result may depend on the values.
 * </p>
 * <p>
 * An attribute whose identifier no mapper declares is left out of the result. That is not an error.
 * </p>
 *
 * @param <O> the protocol representation of an attribute
 * @author Martin Lindström
 * @see FromProtocolAttributeMapper
 */
public interface ToProtocolAttributeMapper<O> {

  /**
   * Gets the generic attribute identifiers that this mapper handles.
   *
   * @return the attribute identifiers
   */
  @Nonnull Collection<String> getSupportedIdentifiers();

  /**
   * Maps the supplied attributes into protocol attributes.
   *
   * @param attributes the attributes whose identifiers this mapper declares, never empty
   * @param context the mapping context
   * @return the resulting protocol attributes, possibly empty
   */
  @Nonnull List<O> map(final @Nonnull List<GenericAttribute<? extends Serializable>> attributes,
      final @Nonnull ToProtocolMappingContext context);

}
