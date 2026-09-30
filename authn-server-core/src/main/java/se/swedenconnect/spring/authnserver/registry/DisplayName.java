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
package se.swedenconnect.spring.authnserver.registry;

import java.io.Serial;
import java.io.Serializable;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.util.StringUtils;

import se.swedenconnect.spring.authnserver.LibraryVersion;

/**
 * A name that a requester may be presented by, in one language.
 *
 * @param language the language tag, or {@code null} for a name that the metadata does not tie to a language
 * @param name the name
 * @author Martin Lindström
 */
public record DisplayName(@Nullable String language, @NonNull String name) implements Serializable {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /**
   * Constructor.
   *
   * @param language the language tag, or {@code null}
   * @param name the name
   */
  public DisplayName {
    Objects.requireNonNull(name, "name must not be null");
    if (language != null && !StringUtils.hasText(language)) {
      throw new IllegalArgumentException("language must not be empty");
    }
    if (!StringUtils.hasText(name)) {
      throw new IllegalArgumentException("name must not be empty");
    }
  }

  /**
   * Gets the primary subtag of the language, which is the part before the first hyphen. For {@code sv-SE} this is
   * {@code sv}.
   *
   * @return the primary language subtag, or {@code null} if the name is not tied to a language
   */
  public @Nullable String getPrimaryLanguage() {
    return primaryLanguage(this.language);
  }

  /**
   * Gets the primary subtag of the supplied language tag, which is the part before the first hyphen. For
   * {@code sv-SE} this is {@code sv}.
   *
   * @param language the language tag, or {@code null}
   * @return the primary language subtag, or {@code null} if no language tag was given
   */
  public static @Nullable String primaryLanguage(final @Nullable String language) {
    if (language == null) {
      return null;
    }
    final int hyphen = language.indexOf('-');
    return hyphen > 0 ? language.substring(0, hyphen) : language;
  }

}
