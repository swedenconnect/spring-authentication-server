/*
 * Copyright 2016-2026 Sweden Connect
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
package se.swedenconnect.spring.authnserver.service.config;

import java.util.ArrayList;
import java.util.List;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration properties for the pages.
 *
 * @author Martin Lindström
 */
@ConfigurationProperties("ui")
public class UiProperties {

  /**
   * The languages that the pages can be shown in.
   */
  private List<Language> languages = new ArrayList<>();

  /**
   * Gets the languages that the pages can be shown in.
   *
   * @return the languages
   */
  public @NonNull List<Language> getLanguages() {
    return this.languages;
  }

  /**
   * Assigns the languages that the pages can be shown in.
   *
   * @param languages the languages
   */
  public void setLanguages(final @Nullable List<Language> languages) {
    this.languages = languages != null ? languages : new ArrayList<>();
  }

  /**
   * A language that the pages can be shown in.
   */
  public static class Language {

    /**
     * The language tag, for example sv.
     */
    private String tag;

    /**
     * The name of the language, as shown on the button that selects it, for example Svenska.
     */
    private String text;

    /**
     * Gets the language tag.
     *
     * @return the language tag
     */
    public @Nullable String getTag() {
      return this.tag;
    }

    /**
     * Assigns the language tag.
     *
     * @param tag the language tag
     */
    public void setTag(final @Nullable String tag) {
      this.tag = tag;
    }

    /**
     * Gets the name of the language.
     *
     * @return the name
     */
    public @Nullable String getText() {
      return this.text;
    }

    /**
     * Assigns the name of the language.
     *
     * @param text the name
     */
    public void setText(final @Nullable String text) {
      this.text = text;
    }

  }

}
