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
 * A logotype that a requester may be presented by.
 * <p>
 * SAML metadata gives the size of a logotype and may give a language, OpenID Connect client metadata gives the URL
 * and, where the {@code logo_uri} parameter carries a language tag, the language.
 * </p>
 *
 * @param language the language tag, or {@code null} for a logotype that the metadata does not tie to a language
 * @param url the URL of the logotype
 * @param height the height in pixels, or {@code null} if the metadata does not give it
 * @param width the width in pixels, or {@code null} if the metadata does not give it
 * @author Martin Lindström
 */
public record Logo(@Nullable String language, @NonNull String url, @Nullable Integer height, @Nullable Integer width)
    implements Serializable {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /**
   * Constructor.
   *
   * @param language the language tag, or {@code null}
   * @param url the URL of the logotype
   * @param height the height in pixels, or {@code null}
   * @param width the width in pixels, or {@code null}
   */
  public Logo {
    Objects.requireNonNull(url, "url must not be null");
    if (language != null && !StringUtils.hasText(language)) {
      throw new IllegalArgumentException("language must not be empty");
    }
    if (!StringUtils.hasText(url)) {
      throw new IllegalArgumentException("url must not be empty");
    }
  }

  /**
   * Gets the primary subtag of the language, which is the part before the first hyphen. For {@code sv-SE} this is
   * {@code sv}.
   *
   * @return the primary language subtag, or {@code null} if the logotype is not tied to a language
   */
  public @Nullable String getPrimaryLanguage() {
    return DisplayName.primaryLanguage(this.language);
  }

  /**
   * Creates a logotype that is not tied to a language and whose size is not known.
   *
   * @param url the URL of the logotype
   * @return a {@link Logo}
   */
  public static @NonNull Logo of(final @NonNull String url) {
    return new Logo(null, url, null, null);
  }

}
