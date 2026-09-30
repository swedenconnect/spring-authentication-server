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
package se.swedenconnect.spring.authnserver.oidc.federation;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.util.StringUtils;

import se.swedenconnect.spring.authnserver.entity.EntityInformation;

/**
 * The descriptive parameters of the OpenID Provider metadata, following
 * <a href="https://docs.swedenconnect.se/federation/oidc-metadata-requirements.html">Sweden Connect - OpenID Connect
 * Metadata Requirements</a>, Section 3.
 * <p>
 * The values are normally taken from the shared {@link EntityInformation}, see
 * {@link #from(EntityInformation, String)}, and each of them may be overridden, see
 * {@link #overriddenBy(OidcEntityMetadata)}. Multilingual values are keyed by language tag and published in the
 * language-tagged form, such as {@code display_name#sv}.
 * </p>
 *
 * @param displayNames the {@code display_name} values, keyed by language tag, or {@code null}
 * @param descriptions the {@code description} values, keyed by language tag, or {@code null}
 * @param organizationNames the {@code organization_name} values, keyed by language tag, or {@code null}
 * @param organizationUri the {@code organization_uri}, or {@code null}
 * @param organizationIdentifier the {@code organization_identifier}, or {@code null}
 * @param logoUri the {@code logo_uri}, or {@code null}
 * @param contacts the {@code contacts}, e-mail addresses, or {@code null}
 * @author Martin Lindström
 */
public record OidcEntityMetadata(
    @Nullable Map<String, String> displayNames,
    @Nullable Map<String, String> descriptions,
    @Nullable Map<String, String> organizationNames,
    @Nullable String organizationUri,
    @Nullable String organizationIdentifier,
    @Nullable String logoUri,
    @Nullable List<String> contacts) {

  /** The prefix of an organization identifier holding a Swedish organization number. */
  public static final String ORGANIZATION_IDENTIFIER_PREFIX = "urn:glue:iso6523:0007:";

  /** The parameter name {@value}. */
  public static final String DISPLAY_NAME = "display_name";

  /** The parameter name {@value}. */
  public static final String DESCRIPTION = "description";

  /** The parameter name {@value}. */
  public static final String ORGANIZATION_NAME = "organization_name";

  /** The parameter name {@value}. */
  public static final String ORGANIZATION_URI = "organization_uri";

  /** The parameter name {@value}. */
  public static final String ORGANIZATION_IDENTIFIER = "organization_identifier";

  /** The parameter name {@value}. */
  public static final String LOGO_URI = "logo_uri";

  /** The parameter name {@value}. */
  public static final String CONTACTS = "contacts";

  /** A ten-digit Swedish organization number. */
  private static final Pattern ORGANIZATION_NUMBER = Pattern.compile("\\d{10}");

  /** A simple check of an e-mail address. */
  private static final Pattern EMAIL_ADDRESS = Pattern.compile("[^@\\s]+@[^@\\s]+");

  /** The prefix that SAML metadata often gives an e-mail address. */
  private static final String MAILTO = "mailto:";

  /**
   * Gets an object holding no values.
   *
   * @return an empty {@link OidcEntityMetadata}
   */
  public static @NonNull OidcEntityMetadata empty() {
    return new OidcEntityMetadata(null, null, null, null, null, null, null);
  }

  /**
   * Maps the descriptive information to the OpenID Connect parameters:
   * <ul>
   * <li>{@code display_name} from the UI display names, and {@code description} from the UI descriptions.</li>
   * <li>{@code organization_name} from the organization names, and {@code organization_uri} from the first
   * organization URL.</li>
   * <li>{@code organization_identifier} as {@code urn:glue:iso6523:0007:<number>} when the organization number is ten
   * digits, and otherwise left out.</li>
   * <li>{@code logo_uri} from the first logo without a language, or else the first logo.</li>
   * <li>{@code contacts} from the e-mail addresses of the technical and support contact persons, without duplicates.
   * A {@code mailto:} prefix is removed.</li>
   * </ul>
   *
   * @param information the entity information
   * @param baseUrl the base URL of the server, for logos given as a path
   * @return an {@link OidcEntityMetadata}
   */
  public static @NonNull OidcEntityMetadata from(final @NonNull EntityInformation information,
      final @NonNull String baseUrl) {
    Objects.requireNonNull(information, "information must not be null");

    Map<String, String> displayNames = null;
    Map<String, String> descriptions = null;
    String logoUri = null;
    final EntityInformation.UiInfo ui = information.uiInfo();
    if (ui != null) {
      displayNames = nonEmpty(ui.displayNames());
      descriptions = nonEmpty(ui.descriptions());
      if (ui.logotypes() != null && !ui.logotypes().isEmpty()) {
        final EntityInformation.Logo logo = ui.logotypes().stream()
            .filter(l -> !StringUtils.hasText(l.languageTag()))
            .findFirst()
            .orElse(ui.logotypes().getFirst());
        logoUri = logo.getUrl(baseUrl);
      }
    }

    Map<String, String> organizationNames = null;
    String organizationUri = null;
    String organizationIdentifier = null;
    final EntityInformation.Organization organization = information.organization();
    if (organization != null) {
      organizationNames = nonEmpty(organization.names());
      if (organization.urls() != null && !organization.urls().isEmpty()) {
        organizationUri = organization.urls().values().iterator().next();
      }
      if (organization.number() != null && ORGANIZATION_NUMBER.matcher(organization.number()).matches()) {
        organizationIdentifier = ORGANIZATION_IDENTIFIER_PREFIX + organization.number();
      }
    }

    List<String> contacts = null;
    if (information.contactPersons() != null) {
      final Set<String> addresses = new LinkedHashSet<>();
      for (final EntityInformation.ContactPersonType type : List.of(
          EntityInformation.ContactPersonType.technical, EntityInformation.ContactPersonType.support)) {
        final EntityInformation.ContactPerson person = information.contactPersons().get(type);
        if (person != null && person.emailAddresses() != null) {
          person.emailAddresses().stream()
              .filter(StringUtils::hasText)
              .map(OidcEntityMetadata::stripMailto)
              .forEach(addresses::add);
        }
      }
      contacts = addresses.isEmpty() ? null : List.copyOf(addresses);
    }
    return new OidcEntityMetadata(displayNames, descriptions, organizationNames, organizationUri,
        organizationIdentifier, logoUri, contacts);
  }

  /**
   * Applies an override. Each value that the override assigns replaces the value here.
   *
   * @param override the override, or {@code null}
   * @return the resulting metadata
   */
  public @NonNull OidcEntityMetadata overriddenBy(final @Nullable OidcEntityMetadata override) {
    if (override == null) {
      return this;
    }
    return new OidcEntityMetadata(
        override.displayNames() != null ? override.displayNames() : this.displayNames,
        override.descriptions() != null ? override.descriptions() : this.descriptions,
        override.organizationNames() != null ? override.organizationNames() : this.organizationNames,
        override.organizationUri() != null ? override.organizationUri() : this.organizationUri,
        override.organizationIdentifier() != null ? override.organizationIdentifier() : this.organizationIdentifier,
        override.logoUri() != null ? override.logoUri() : this.logoUri,
        override.contacts() != null ? override.contacts() : this.contacts);
  }

  /**
   * Gets the values as metadata parameters. A multilingual value gives one parameter per language, such as
   * {@code display_name#sv} and {@code display_name#en}.
   *
   * @return the parameters, in a map that the caller may change
   */
  public @NonNull Map<String, Object> toParameters() {
    final Map<String, Object> parameters = new LinkedHashMap<>();
    addLanguageTagged(parameters, DISPLAY_NAME, this.displayNames);
    addLanguageTagged(parameters, DESCRIPTION, this.descriptions);
    addLanguageTagged(parameters, ORGANIZATION_NAME, this.organizationNames);
    if (StringUtils.hasText(this.organizationUri)) {
      parameters.put(ORGANIZATION_URI, this.organizationUri);
    }
    if (StringUtils.hasText(this.organizationIdentifier)) {
      parameters.put(ORGANIZATION_IDENTIFIER, this.organizationIdentifier);
    }
    if (StringUtils.hasText(this.logoUri)) {
      parameters.put(LOGO_URI, this.logoUri);
    }
    if (this.contacts != null && !this.contacts.isEmpty()) {
      parameters.put(CONTACTS, new ArrayList<>(this.contacts));
    }
    return parameters;
  }

  /**
   * Checks the values that the Sweden Connect federation requires of an entity configuration: {@code contacts} holds
   * at least one e-mail address, and {@code logo_uri} is an HTTPS URL.
   *
   * @throws IllegalArgumentException if a value is missing or invalid
   */
  public void validate() {
    if (this.contacts == null || this.contacts.stream().noneMatch(c -> EMAIL_ADDRESS.matcher(c).matches())) {
      throw new IllegalArgumentException("The OIDC entity metadata must have at least one e-mail address in "
          + "contacts - give a technical or support contact person with an e-mail address, or assign contacts");
    }
    if (this.logoUri == null || !this.logoUri.startsWith("https://")) {
      throw new IllegalArgumentException(
          "The OIDC entity metadata must have a logo_uri that is an HTTPS URL - it is '%s'".formatted(this.logoUri));
    }
  }

  /**
   * Adds a multilingual value as one parameter per language.
   *
   * @param parameters the parameters
   * @param name the parameter name
   * @param values the values, keyed by language tag, or {@code null}
   */
  private static void addLanguageTagged(final @NonNull Map<String, Object> parameters, final @NonNull String name,
      final @Nullable Map<String, String> values) {
    if (values == null) {
      return;
    }
    values.forEach((language, value) -> {
      if (StringUtils.hasText(value)) {
        parameters.put(StringUtils.hasText(language) ? name + "#" + language : name, value);
      }
    });
  }

  /**
   * Gives {@code null} for an empty map.
   *
   * @param map the map
   * @return the map, or {@code null} if it is empty
   */
  private static @Nullable Map<String, String> nonEmpty(final @Nullable Map<String, String> map) {
    return map == null || map.isEmpty() ? null : map;
  }

  /**
   * Removes a {@code mailto:} prefix.
   *
   * @param address the address
   * @return the address without the prefix
   */
  private static @NonNull String stripMailto(final @NonNull String address) {
    final String trimmed = address.trim();
    return trimmed.regionMatches(true, 0, MAILTO, 0, MAILTO.length()) ? trimmed.substring(MAILTO.length()) : trimmed;
  }

}
