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
package se.swedenconnect.spring.authnserver.saml.attributes;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiConsumer;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import se.swedenconnect.opensaml.eidas.ext.attributes.AttributeUtils;
import se.swedenconnect.opensaml.eidas.ext.attributes.CurrentAddressType;
import se.swedenconnect.spring.authnserver.attributes.AttributeIdentifiers;

/**
 * The {@code eidasNaturalPersonAddress} SAML attribute, which holds the eIDAS {@code CurrentAddress} attribute of a
 * natural person as key-value pairs separated by semicolons, where the key and the value are URL-encoded.
 * <p>
 * See Section 3.3.3.1 of the Attribute Specification for the Swedish eID Framework. Each key is a generic attribute of
 * its own.
 * </p>
 * <p>
 * The attribute value is produced by {@link CurrentAddressType#toSwedishEidString()}. Reading such a value back is not
 * supported by OpenSAML, so {@link #parse(String)} does that here.
 * </p>
 *
 * @author Martin Lindström
 */
public class EidasNaturalPersonAddress {

  /** Mapping from the keys of the attribute to the generic attribute identifiers, in the order of the eIDAS schema. */
  private static final Map<String, String> KEY_TO_IDENTIFIER = new LinkedHashMap<>();

  /** The setter of {@link CurrentAddressType} for each generic attribute identifier. */
  private static final Map<String, BiConsumer<CurrentAddressType, String>> SETTERS = new LinkedHashMap<>();

  static {
    KEY_TO_IDENTIFIER.put("PoBox", AttributeIdentifiers.EIDAS_ADDRESS_PO_BOX);
    KEY_TO_IDENTIFIER.put("LocatorDesignator", AttributeIdentifiers.EIDAS_ADDRESS_LOCATOR_DESIGNATOR);
    KEY_TO_IDENTIFIER.put("LocatorName", AttributeIdentifiers.EIDAS_ADDRESS_LOCATOR_NAME);
    KEY_TO_IDENTIFIER.put("CvaddressArea", AttributeIdentifiers.EIDAS_ADDRESS_AREA);
    KEY_TO_IDENTIFIER.put("Thoroughfare", AttributeIdentifiers.EIDAS_ADDRESS_THOROUGHFARE);
    KEY_TO_IDENTIFIER.put("PostName", AttributeIdentifiers.EIDAS_ADDRESS_POST_NAME);
    KEY_TO_IDENTIFIER.put("AdminunitFirstline", AttributeIdentifiers.EIDAS_ADDRESS_ADMIN_UNIT_FIRST_LINE);
    KEY_TO_IDENTIFIER.put("AdminunitSecondline", AttributeIdentifiers.EIDAS_ADDRESS_ADMIN_UNIT_SECOND_LINE);
    KEY_TO_IDENTIFIER.put("PostCode", AttributeIdentifiers.EIDAS_ADDRESS_POST_CODE);

    SETTERS.put(AttributeIdentifiers.EIDAS_ADDRESS_PO_BOX, CurrentAddressType::setPoBox);
    SETTERS.put(AttributeIdentifiers.EIDAS_ADDRESS_LOCATOR_DESIGNATOR, CurrentAddressType::setLocatorDesignator);
    SETTERS.put(AttributeIdentifiers.EIDAS_ADDRESS_LOCATOR_NAME, CurrentAddressType::setLocatorName);
    SETTERS.put(AttributeIdentifiers.EIDAS_ADDRESS_AREA, CurrentAddressType::setCvaddressArea);
    SETTERS.put(AttributeIdentifiers.EIDAS_ADDRESS_THOROUGHFARE, CurrentAddressType::setThoroughfare);
    SETTERS.put(AttributeIdentifiers.EIDAS_ADDRESS_POST_NAME, CurrentAddressType::setPostName);
    SETTERS.put(AttributeIdentifiers.EIDAS_ADDRESS_ADMIN_UNIT_FIRST_LINE, CurrentAddressType::setAdminunitFirstline);
    SETTERS.put(AttributeIdentifiers.EIDAS_ADDRESS_ADMIN_UNIT_SECOND_LINE, CurrentAddressType::setAdminunitSecondline);
    SETTERS.put(AttributeIdentifiers.EIDAS_ADDRESS_POST_CODE, CurrentAddressType::setPostCode);
  }

  /**
   * Gets the generic attribute identifiers that the parts of the address map to, in the order of the eIDAS schema.
   *
   * @return the attribute identifiers
   */
  public static @NonNull List<String> getIdentifiers() {
    return List.copyOf(KEY_TO_IDENTIFIER.values());
  }

  /**
   * Parses an {@code eidasNaturalPersonAddress} attribute value into generic attribute identifiers and their values.
   * Pairs whose key is not part of the eIDAS address are ignored.
   *
   * @param value the attribute value
   * @return a map from generic attribute identifier to value
   */
  public static @NonNull Map<String, String> parse(final @Nullable String value) {
    final Map<String, String> result = new LinkedHashMap<>();
    if (value == null || value.isBlank()) {
      return result;
    }
    for (final String pair : value.split(";")) {
      final int separator = pair.indexOf('=');
      if (separator < 1) {
        continue;
      }
      final String key = decode(pair.substring(0, separator).trim());
      final String identifier = KEY_TO_IDENTIFIER.get(key);
      if (identifier != null) {
        result.put(identifier, decode(pair.substring(separator + 1).trim()));
      }
    }
    return result;
  }

  /**
   * Builds an {@code eidasNaturalPersonAddress} attribute value from generic attribute identifiers and their values.
   * Identifiers that are not part of the eIDAS address are ignored.
   *
   * @param values a map from generic attribute identifier to value
   * @return the attribute value, or {@code null} if no part of the address was supplied
   */
  public static @Nullable String format(final @NonNull Map<String, String> values) {
    final CurrentAddressType address = toCurrentAddress(values);
    return address != null ? address.toSwedishEidString() : null;
  }

  /**
   * Builds an eIDAS {@code CurrentAddress} from generic attribute identifiers and their values.
   *
   * @param values a map from generic attribute identifier to value
   * @return a {@link CurrentAddressType}, or {@code null} if no part of the address was supplied
   */
  public static @Nullable CurrentAddressType toCurrentAddress(final @NonNull Map<String, String> values) {
    CurrentAddressType address = null;
    for (final Map.Entry<String, BiConsumer<CurrentAddressType, String>> setter : SETTERS.entrySet()) {
      final String value = values.get(setter.getKey());
      if (value == null || value.isEmpty()) {
        continue;
      }
      if (address == null) {
        address = AttributeUtils.createAttributeValueObject(CurrentAddressType.TYPE_NAME, CurrentAddressType.class);
      }
      setter.getValue().accept(address, value);
    }
    return address;
  }

  /**
   * URL-decodes a string.
   *
   * @param value the value to decode
   * @return the decoded value
   */
  private static @NonNull String decode(final @NonNull String value) {
    return URLDecoder.decode(value, StandardCharsets.UTF_8);
  }

  // Hidden constructor
  private EidasNaturalPersonAddress() {
  }

}
