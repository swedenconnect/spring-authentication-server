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
package se.swedenconnect.spring.authnserver.message;

import java.io.Serial;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.util.StringUtils;

import se.swedenconnect.spring.authnserver.LibraryVersion;

/**
 * A message in one language.
 * <p>
 * Both the SAML and the OpenID Connect specifications carry the message as the Base64 encoding of the UTF-8 string that
 * is to be shown, so that is how the message is held here. Use {@link #getText()} to get the string itself.
 * </p>
 *
 * @param language the language tag of the message, or {@code null} for a message that is not tied to a language. SAML
 *          requires a language for every message, OpenID Connect allows one message without one
 * @param message the Base64 encoding of the UTF-8 message
 * @author Martin Lindström
 */
public record LocalizedMessage(@Nullable String language, @NonNull String message) implements Serializable {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /**
   * Constructor.
   *
   * @param language the language tag, or {@code null}
   * @param message the Base64 encoding of the UTF-8 message
   */
  public LocalizedMessage {
    if (language != null && !StringUtils.hasText(language)) {
      throw new IllegalArgumentException("language must not be empty");
    }
    if (!StringUtils.hasText(message)) {
      throw new IllegalArgumentException("message must be set and not empty");
    }
    try {
      Base64.getDecoder().decode(message);
    }
    catch (final IllegalArgumentException e) {
      throw new IllegalArgumentException("message must be Base64 encoded", e);
    }
  }

  /**
   * Creates a message from the string that is to be shown to the user.
   *
   * @param language the language tag, or {@code null}
   * @param text the message text
   * @return a {@link LocalizedMessage}
   */
  public static @NonNull LocalizedMessage ofText(final @Nullable String language, final @NonNull String text) {
    Objects.requireNonNull(text, "text must not be null");
    return new LocalizedMessage(language,
        Base64.getEncoder().encodeToString(text.getBytes(StandardCharsets.UTF_8)));
  }

  /**
   * Gets the message text, that is, the decoded message.
   *
   * @return the message text
   */
  public @NonNull String getText() {
    return new String(Base64.getDecoder().decode(this.message), StandardCharsets.UTF_8);
  }

  /**
   * Gets the primary subtag of the message language, which is the part before the first hyphen. For {@code sv-SE} this
   * is {@code sv}.
   *
   * @return the primary language subtag, or {@code null} if the message is not tied to a language
   */
  public @Nullable String getPrimaryLanguage() {
    if (this.language == null) {
      return null;
    }
    final int hyphen = this.language.indexOf('-');
    return hyphen > 0 ? this.language.substring(0, hyphen) : this.language;
  }

}
