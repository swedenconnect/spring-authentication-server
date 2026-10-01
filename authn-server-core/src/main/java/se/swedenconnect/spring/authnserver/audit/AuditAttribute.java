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
package se.swedenconnect.spring.authnserver.audit;

import java.io.Serial;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Objects;

import org.jspecify.annotations.NonNull;

import se.swedenconnect.spring.authnserver.LibraryVersion;
import se.swedenconnect.spring.authnserver.attributes.GenericAttribute;

/**
 * An attribute as an audit event records it: its name and its values as strings. The name is the protocol-neutral
 * identifier for the attributes that the authenticator delivered, and the SAML attribute name or the OpenID Connect
 * claim name for the attributes that were released.
 *
 * @param name the name of the attribute
 * @param values the values, as strings
 * @author Martin Lindström
 */
public record AuditAttribute(@NonNull String name, @NonNull List<String> values) implements Serializable {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /**
   * Constructor.
   *
   * @param name the name of the attribute
   * @param values the values
   */
  public AuditAttribute {
    Objects.requireNonNull(name, "name must not be null");
    values = List.copyOf(Objects.requireNonNull(values, "values must not be null"));
  }

  /**
   * Creates an audit attribute from a protocol-neutral attribute.
   *
   * @param attribute the attribute
   * @return an {@link AuditAttribute}
   */
  public static @NonNull AuditAttribute of(final @NonNull GenericAttribute<?> attribute) {
    return new AuditAttribute(attribute.getIdentifier(), attribute.getStringValues());
  }

  /**
   * Gets the attribute as the object written to the audit event, with the members {@code name} and {@code values}.
   *
   * @return a map
   */
  public @NonNull LinkedHashMap<String, Serializable> toMap() {
    final LinkedHashMap<String, Serializable> map = new LinkedHashMap<>();
    map.put("name", this.name);
    map.put("values", new ArrayList<>(this.values));
    return map;
  }

}
