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
package se.swedenconnect.spring.authnserver.saml.config;

import java.util.List;
import java.util.Map;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * The elements of the IdP metadata that are given as values to the {@link Saml2IdpMetadataEndpointConfigurer}.
 *
 * @author Martin Lindström
 */
public final class IdpMetadataElements {

  /**
   * An {@code mdui:UIInfo} element.
   *
   * @param displayNames the display names, keyed by language tag
   * @param descriptions the descriptions, keyed by language tag
   * @param logotypes the logotypes
   */
  public record UiInfo(@Nullable Map<String, String> displayNames, @Nullable Map<String, String> descriptions,
      @Nullable List<Logo> logotypes) {
  }

  /**
   * An {@code mdui:Logo} element. Exactly one of {@code url} and {@code path} is given.
   *
   * @param url the logotype URL
   * @param path the logotype path, relative to the base URL
   * @param height the height in pixels
   * @param width the width in pixels
   * @param languageTag the language tag, or {@code null}
   */
  public record Logo(@Nullable String url, @Nullable String path, @Nullable Integer height, @Nullable Integer width,
      @Nullable String languageTag) {
  }

  /**
   * An {@code md:Organization} element.
   *
   * @param names the {@code OrganizationName} elements, keyed by language tag
   * @param displayNames the {@code OrganizationDisplayName} elements, keyed by language tag
   * @param urls the {@code OrganizationURL} elements, keyed by language tag
   * @param number the organisation number, published as {@code mdorgext:OrganizationNumber}, or {@code null}
   */
  public record Organization(@Nullable Map<String, String> names, @Nullable Map<String, String> displayNames,
      @Nullable Map<String, String> urls, @Nullable String number) {
  }

  /**
   * The type of an {@code md:ContactPerson} element. {@code security} is published as {@code other} with the REFEDS
   * security contact type.
   */
  public enum ContactPersonType {
    /** Technical contact. */
    technical,
    /** Support contact. */
    support,
    /** Administrative contact. */
    administrative,
    /** Billing contact. */
    billing,
    /** Other contact. */
    other,
    /** Security contact. */
    security
  }

  /**
   * An {@code md:ContactPerson} element.
   *
   * @param company the company
   * @param givenName the given name
   * @param surname the surname
   * @param emailAddresses the e-mail addresses
   * @param telephoneNumbers the telephone numbers
   */
  public record ContactPerson(@Nullable String company, @Nullable String givenName, @Nullable String surname,
      @Nullable List<String> emailAddresses, @Nullable List<String> telephoneNumbers) {
  }

  /**
   * An {@code alg:SigningMethod} element.
   *
   * @param algorithm the algorithm URI
   * @param minKeySize the smallest key size in bits, or {@code null}
   * @param maxKeySize the largest key size in bits, or {@code null}
   */
  public record SigningMethod(@NonNull String algorithm, @Nullable Integer minKeySize, @Nullable Integer maxKeySize) {
  }

  /**
   * An {@code md:EncryptionMethod} element, placed under the {@code md:KeyDescriptor} of the encryption key.
   *
   * @param algorithm the algorithm URI
   * @param keySize the key size, or {@code null}
   * @param oaepParams the OAEP parameters in Base64, or {@code null}
   * @param digestMethod the digest algorithm URI for key transport algorithms that need one, or {@code null}
   */
  public record EncryptionMethod(@NonNull String algorithm, @Nullable Integer keySize, @Nullable String oaepParams,
      @Nullable String digestMethod) {
  }

  // Hidden constructor
  private IdpMetadataElements() {
  }

}
