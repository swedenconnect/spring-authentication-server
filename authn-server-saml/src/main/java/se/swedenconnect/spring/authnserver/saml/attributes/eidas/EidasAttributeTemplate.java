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
package se.swedenconnect.spring.authnserver.saml.attributes.eidas;

import jakarta.annotation.Nonnull;

import java.util.Objects;

import javax.xml.namespace.QName;

import org.opensaml.core.xml.XMLObject;

/**
 * A description of an eIDAS attribute: its name, its friendly name and the XML type of its values.
 * <p>
 * eIDAS attributes do not use plain string values. Each attribute has an XML type of its own, see Section 2.2 of the
 * eIDAS SAML Attribute Profile, and the type is what tells us how to build and read a value.
 * </p>
 *
 * @param name the eIDAS attribute name
 * @param friendlyName the eIDAS attribute friendly name
 * @param valueTypeName the XML type name of the attribute values
 * @param valueType the Java type of the attribute values
 * @author Martin Lindström
 */
public record EidasAttributeTemplate(@Nonnull String name, @Nonnull String friendlyName,
    @Nonnull QName valueTypeName, @Nonnull Class<? extends XMLObject> valueType) {

  /**
   * Constructor.
   *
   * @param name the eIDAS attribute name
   * @param friendlyName the eIDAS attribute friendly name
   * @param valueTypeName the XML type name of the attribute values
   * @param valueType the Java type of the attribute values
   */
  public EidasAttributeTemplate {
    Objects.requireNonNull(name, "name must not be null");
    Objects.requireNonNull(friendlyName, "friendlyName must not be null");
    Objects.requireNonNull(valueTypeName, "valueTypeName must not be null");
    Objects.requireNonNull(valueType, "valueType must not be null");
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return "%s (%s)".formatted(this.name, this.friendlyName);
  }

}
