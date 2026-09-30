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
package se.swedenconnect.spring.authnserver.autoconfigure;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import se.swedenconnect.spring.authnserver.entity.EntityInformation;
import se.swedenconnect.spring.authnserver.entity.EntityInformation.ContactPersonType;

/**
 * Properties for the descriptive information about the server and its organization that the protocols publish. The
 * same shape is used for the shared information and for the protocol overrides.
 *
 * @author Martin Lindström
 */
public class EntityInformationProperties {

  /**
   * The display names, descriptions and logos of the service.
   */
  private UiInfo uiInfo;

  /**
   * The organization.
   */
  private Organization organization;

  /**
   * The contact persons, keyed by type: technical, support, administrative, billing, other or security.
   */
  private Map<ContactPersonType, ContactPerson> contactPersons;

  /**
   * Gets the UI information.
   *
   * @return the UI information
   */
  public @Nullable UiInfo getUiInfo() {
    return this.uiInfo;
  }

  /**
   * Assigns the UI information.
   *
   * @param uiInfo the UI information
   */
  public void setUiInfo(final @Nullable UiInfo uiInfo) {
    this.uiInfo = uiInfo;
  }

  /**
   * Gets the organization.
   *
   * @return the organization
   */
  public @Nullable Organization getOrganization() {
    return this.organization;
  }

  /**
   * Assigns the organization.
   *
   * @param organization the organization
   */
  public void setOrganization(final @Nullable Organization organization) {
    this.organization = organization;
  }

  /**
   * Gets the contact persons.
   *
   * @return the contact persons
   */
  public @Nullable Map<ContactPersonType, ContactPerson> getContactPersons() {
    return this.contactPersons;
  }

  /**
   * Assigns the contact persons.
   *
   * @param contactPersons the contact persons
   */
  public void setContactPersons(final @Nullable Map<ContactPersonType, ContactPerson> contactPersons) {
    this.contactPersons = contactPersons;
  }

  /**
   * Creates the {@link EntityInformation} of the properties.
   *
   * @return an {@link EntityInformation}, which is empty when nothing is assigned
   */
  public @NonNull EntityInformation toEntityInformation() {
    return toEntityInformation(this.uiInfo, this.organization, this.contactPersons);
  }

  /**
   * Creates an {@link EntityInformation} from property values.
   *
   * @param uiInfo the UI information, or {@code null}
   * @param organization the organization, or {@code null}
   * @param contactPersons the contact persons, or {@code null}
   * @return an {@link EntityInformation}
   */
  public static @NonNull EntityInformation toEntityInformation(final @Nullable UiInfo uiInfo,
      final @Nullable Organization organization, final @Nullable Map<ContactPersonType, ContactPerson> contactPersons) {

    EntityInformation.UiInfo ui = null;
    if (uiInfo != null) {
      ui = new EntityInformation.UiInfo(uiInfo.getDisplayNames(), uiInfo.getDescriptions(),
          uiInfo.getLogotypes() != null
              ? uiInfo.getLogotypes().stream()
                  .map(l -> new EntityInformation.Logo(l.getUrl(), l.getPath(), l.getHeight(), l.getWidth(),
                      l.getLanguageTag()))
                  .toList()
              : null);
    }
    EntityInformation.Organization org = null;
    if (organization != null) {
      org = new EntityInformation.Organization(organization.getNames(), organization.getDisplayNames(),
          organization.getUrls(), organization.getNumber());
    }
    Map<ContactPersonType, EntityInformation.ContactPerson> contacts = null;
    if (contactPersons != null) {
      contacts = new LinkedHashMap<>();
      for (final Map.Entry<ContactPersonType, ContactPerson> e : contactPersons.entrySet()) {
        final ContactPerson c = e.getValue();
        contacts.put(e.getKey(), new EntityInformation.ContactPerson(c.getCompany(), c.getGivenName(),
            c.getSurname(), c.getEmailAddresses(), c.getTelephoneNumbers()));
      }
    }
    return new EntityInformation(ui, org, contacts);
  }

  /**
   * The display names, descriptions and logos of the service.
   */
  public static class UiInfo {

    /**
     * Display names, keyed by language tag.
     */
    private Map<String, String> displayNames;

    /**
     * Descriptions, keyed by language tag.
     */
    private Map<String, String> descriptions;

    /**
     * Logotypes.
     */
    private List<Logo> logotypes;

    /**
     * Gets the display names.
     *
     * @return the display names
     */
    public @Nullable Map<String, String> getDisplayNames() {
      return this.displayNames;
    }

    /**
     * Assigns the display names.
     *
     * @param displayNames the display names
     */
    public void setDisplayNames(final @Nullable Map<String, String> displayNames) {
      this.displayNames = displayNames;
    }

    /**
     * Gets the descriptions.
     *
     * @return the descriptions
     */
    public @Nullable Map<String, String> getDescriptions() {
      return this.descriptions;
    }

    /**
     * Assigns the descriptions.
     *
     * @param descriptions the descriptions
     */
    public void setDescriptions(final @Nullable Map<String, String> descriptions) {
      this.descriptions = descriptions;
    }

    /**
     * Gets the logotypes.
     *
     * @return the logotypes
     */
    public @Nullable List<Logo> getLogotypes() {
      return this.logotypes;
    }

    /**
     * Assigns the logotypes.
     *
     * @param logotypes the logotypes
     */
    public void setLogotypes(final @Nullable List<Logo> logotypes) {
      this.logotypes = logotypes;
    }

    /**
     * A logo.
     */
    public static class Logo {

      /**
       * The logotype URL. Mutually exclusive with path.
       */
      private String url;

      /**
       * The logotype path, relative to the base URL. Mutually exclusive with url.
       */
      private String path;

      /**
       * The height in pixels.
       */
      private Integer height;

      /**
       * The width in pixels.
       */
      private Integer width;

      /**
       * The language tag.
       */
      private String languageTag;

      /**
       * Gets the logotype URL.
       *
       * @return the logotype URL
       */
      public @Nullable String getUrl() {
        return this.url;
      }

      /**
       * Assigns the logotype URL.
       *
       * @param url the logotype URL
       */
      public void setUrl(final @Nullable String url) {
        this.url = url;
      }

      /**
       * Gets the logotype path.
       *
       * @return the logotype path
       */
      public @Nullable String getPath() {
        return this.path;
      }

      /**
       * Assigns the logotype path.
       *
       * @param path the logotype path
       */
      public void setPath(final @Nullable String path) {
        this.path = path;
      }

      /**
       * Gets the height.
       *
       * @return the height
       */
      public @Nullable Integer getHeight() {
        return this.height;
      }

      /**
       * Assigns the height.
       *
       * @param height the height
       */
      public void setHeight(final @Nullable Integer height) {
        this.height = height;
      }

      /**
       * Gets the width.
       *
       * @return the width
       */
      public @Nullable Integer getWidth() {
        return this.width;
      }

      /**
       * Assigns the width.
       *
       * @param width the width
       */
      public void setWidth(final @Nullable Integer width) {
        this.width = width;
      }

      /**
       * Gets the language tag.
       *
       * @return the language tag
       */
      public @Nullable String getLanguageTag() {
        return this.languageTag;
      }

      /**
       * Assigns the language tag.
       *
       * @param languageTag the language tag
       */
      public void setLanguageTag(final @Nullable String languageTag) {
        this.languageTag = languageTag;
      }
    }
  }

  /**
   * The organization.
   */
  public static class Organization {

    /**
     * The names of the organization, keyed by language tag.
     */
    private Map<String, String> names;

    /**
     * The display names of the organization, keyed by language tag.
     */
    private Map<String, String> displayNames;

    /**
     * The URLs of the organization, keyed by language tag.
     */
    private Map<String, String> urls;

    /**
     * The organization number. For SAML it is published as mdorgext:OrganizationNumber, and for OpenID Connect a
     * ten-digit number gives organization_identifier.
     */
    private String number;

    /**
     * Gets the organisation names.
     *
     * @return the organisation names
     */
    public @Nullable Map<String, String> getNames() {
      return this.names;
    }

    /**
     * Assigns the organisation names.
     *
     * @param names the organisation names
     */
    public void setNames(final @Nullable Map<String, String> names) {
      this.names = names;
    }

    /**
     * Gets the organisation display names.
     *
     * @return the organisation display names
     */
    public @Nullable Map<String, String> getDisplayNames() {
      return this.displayNames;
    }

    /**
     * Assigns the organisation display names.
     *
     * @param displayNames the organisation display names
     */
    public void setDisplayNames(final @Nullable Map<String, String> displayNames) {
      this.displayNames = displayNames;
    }

    /**
     * Gets the organisation URLs.
     *
     * @return the organisation URLs
     */
    public @Nullable Map<String, String> getUrls() {
      return this.urls;
    }

    /**
     * Assigns the organisation URLs.
     *
     * @param urls the organisation URLs
     */
    public void setUrls(final @Nullable Map<String, String> urls) {
      this.urls = urls;
    }

    /**
     * Gets the organisation number.
     *
     * @return the organisation number
     */
    public @Nullable String getNumber() {
      return this.number;
    }

    /**
     * Assigns the organisation number.
     *
     * @param number the organisation number
     */
    public void setNumber(final @Nullable String number) {
      this.number = number;
    }
  }

  /**
   * A contact person.
   */
  public static class ContactPerson {

    /**
     * The company.
     */
    private String company;

    /**
     * The given name.
     */
    private String givenName;

    /**
     * The surname.
     */
    private String surname;

    /**
     * The e-mail addresses.
     */
    private List<String> emailAddresses;

    /**
     * The telephone numbers.
     */
    private List<String> telephoneNumbers;

    /**
     * Gets the company.
     *
     * @return the company
     */
    public @Nullable String getCompany() {
      return this.company;
    }

    /**
     * Assigns the company.
     *
     * @param company the company
     */
    public void setCompany(final @Nullable String company) {
      this.company = company;
    }

    /**
     * Gets the given name.
     *
     * @return the given name
     */
    public @Nullable String getGivenName() {
      return this.givenName;
    }

    /**
     * Assigns the given name.
     *
     * @param givenName the given name
     */
    public void setGivenName(final @Nullable String givenName) {
      this.givenName = givenName;
    }

    /**
     * Gets the surname.
     *
     * @return the surname
     */
    public @Nullable String getSurname() {
      return this.surname;
    }

    /**
     * Assigns the surname.
     *
     * @param surname the surname
     */
    public void setSurname(final @Nullable String surname) {
      this.surname = surname;
    }

    /**
     * Gets the e-mail addresses.
     *
     * @return the e-mail addresses
     */
    public @Nullable List<String> getEmailAddresses() {
      return this.emailAddresses;
    }

    /**
     * Assigns the e-mail addresses.
     *
     * @param emailAddresses the e-mail addresses
     */
    public void setEmailAddresses(final @Nullable List<String> emailAddresses) {
      this.emailAddresses = emailAddresses;
    }

    /**
     * Gets the telephone numbers.
     *
     * @return the telephone numbers
     */
    public @Nullable List<String> getTelephoneNumbers() {
      return this.telephoneNumbers;
    }

    /**
     * Assigns the telephone numbers.
     *
     * @param telephoneNumbers the telephone numbers
     */
    public void setTelephoneNumbers(final @Nullable List<String> telephoneNumbers) {
      this.telephoneNumbers = telephoneNumbers;
    }
  }

}
