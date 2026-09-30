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
package se.swedenconnect.spring.authnserver.entity;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * The descriptive information about the server and its organization that the protocols publish: the SAML metadata
 * and the OpenID Federation entity configuration.
 * <p>
 * The information is given once, for all protocols, and a protocol may override any part of it. See
 * {@link #overriddenBy(EntityInformation)} for how an override is applied.
 * </p>
 *
 * @param uiInfo the display names, descriptions and logos of the service, or {@code null}
 * @param organization the organization, or {@code null}
 * @param contactPersons the contact persons, keyed by type, or {@code null}
 * @author Martin Lindström
 */
public record EntityInformation(
    @Nullable UiInfo uiInfo,
    @Nullable Organization organization,
    @Nullable Map<ContactPersonType, ContactPerson> contactPersons) {

  /**
   * Gets an object holding no information.
   *
   * @return an empty {@link EntityInformation}
   */
  public static @NonNull EntityInformation empty() {
    return new EntityInformation(null, null, null);
  }

  /**
   * Tells whether the object holds no information.
   *
   * @return {@code true} if nothing is assigned and {@code false} otherwise
   */
  public boolean isEmpty() {
    return this.uiInfo == null && this.organization == null && this.contactPersons == null;
  }

  /**
   * Applies an override to this information. Each value that the override assigns replaces the value here: the
   * display names, the descriptions and the logos of the UI information, and the names, display names, URLs and number
   * of the organization, each as a whole. A contact person of the override replaces the contact person of the same
   * type, and the other contact persons are kept.
   *
   * @param override the override, or {@code null}
   * @return the resulting information
   */
  public @NonNull EntityInformation overriddenBy(final @Nullable EntityInformation override) {
    if (override == null || override.isEmpty()) {
      return this;
    }
    final UiInfo ui = this.uiInfo == null
        ? override.uiInfo()
        : this.uiInfo.overriddenBy(override.uiInfo());
    final Organization org = this.organization == null
        ? override.organization()
        : this.organization.overriddenBy(override.organization());

    Map<ContactPersonType, ContactPerson> contacts = this.contactPersons;
    if (override.contactPersons() != null) {
      if (contacts == null) {
        contacts = override.contactPersons();
      }
      else {
        final Map<ContactPersonType, ContactPerson> merged = new LinkedHashMap<>(contacts);
        merged.putAll(override.contactPersons());
        contacts = merged;
      }
    }
    return new EntityInformation(ui, org, contacts);
  }

  /**
   * The display names, descriptions and logos of the service, as shown to users.
   *
   * @param displayNames the display names, keyed by language tag, or {@code null}
   * @param descriptions the descriptions, keyed by language tag, or {@code null}
   * @param logotypes the logos, or {@code null}
   */
  public record UiInfo(
      @Nullable Map<String, String> displayNames,
      @Nullable Map<String, String> descriptions,
      @Nullable List<Logo> logotypes) {

    /**
     * Applies an override. Each value that the override assigns replaces the value here.
     *
     * @param override the override, or {@code null}
     * @return the resulting UI information
     */
    public @NonNull UiInfo overriddenBy(final @Nullable UiInfo override) {
      if (override == null) {
        return this;
      }
      return new UiInfo(
          override.displayNames() != null ? override.displayNames() : this.displayNames,
          override.descriptions() != null ? override.descriptions() : this.descriptions,
          override.logotypes() != null ? override.logotypes() : this.logotypes);
    }
  }

  /**
   * A logo. It has either a URL or a path relative to the base URL of the server.
   *
   * @param url the URL of the logo, or {@code null} when a path is given
   * @param path the path of the logo, relative to the base URL, or {@code null} when a URL is given
   * @param height the height in pixels, or {@code null}
   * @param width the width in pixels, or {@code null}
   * @param languageTag the language of the logo, or {@code null} if it has none
   */
  public record Logo(
      @Nullable String url,
      @Nullable String path,
      @Nullable Integer height,
      @Nullable Integer width,
      @Nullable String languageTag) {

    /**
     * Gets the URL of the logo: the URL when one is given, and otherwise the base URL followed by the path.
     *
     * @param baseUrl the base URL of the server
     * @return the URL, or {@code null} if neither a URL nor a path is given
     */
    public @Nullable String getUrl(final @NonNull String baseUrl) {
      return this.path != null ? baseUrl + this.path : this.url;
    }
  }

  /**
   * The organization behind the service.
   *
   * @param names the names of the organization, keyed by language tag, or {@code null}
   * @param displayNames the display names of the organization, keyed by language tag, or {@code null}
   * @param urls the URLs of the organization, keyed by language tag, or {@code null}
   * @param number the organization number, or {@code null}
   */
  public record Organization(
      @Nullable Map<String, String> names,
      @Nullable Map<String, String> displayNames,
      @Nullable Map<String, String> urls,
      @Nullable String number) {

    /**
     * Applies an override. Each value that the override assigns replaces the value here.
     *
     * @param override the override, or {@code null}
     * @return the resulting organization
     */
    public @NonNull Organization overriddenBy(final @Nullable Organization override) {
      if (override == null) {
        return this;
      }
      return new Organization(
          override.names() != null ? override.names() : this.names,
          override.displayNames() != null ? override.displayNames() : this.displayNames,
          override.urls() != null ? override.urls() : this.urls,
          override.number() != null ? override.number() : this.number);
    }
  }

  /**
   * The type of a contact person.
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
   * A contact person.
   *
   * @param company the company, or {@code null}
   * @param givenName the given name, or {@code null}
   * @param surname the surname, or {@code null}
   * @param emailAddresses the e-mail addresses, or {@code null}
   * @param telephoneNumbers the telephone numbers, or {@code null}
   */
  public record ContactPerson(
      @Nullable String company,
      @Nullable String givenName,
      @Nullable String surname,
      @Nullable List<String> emailAddresses,
      @Nullable List<String> telephoneNumbers) {
  }

}
