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

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;

import java.io.Serial;
import java.io.Serializable;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

import se.swedenconnect.spring.authnserver.LibraryVersion;

/**
 * Base class for the messages that a requester may ask the server to show to the user. A message is given in one or
 * more languages, and all the languages share one MIME type.
 *
 * @author Martin Lindström
 */
public abstract class GenericMessage implements Serializable {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /** The message in each of the languages it was given in. */
  private final List<LocalizedMessage> messages;

  /** The MIME type of all the messages. */
  private final MessageMimeType mimeType;

  /**
   * Constructor.
   *
   * @param messages the message in each of the languages it was given in, must not be empty. At most one of them may be
   *          without a language, and no language may appear more than once
   * @param mimeType the MIME type of all the messages, {@link MessageMimeType#TEXT_PLAIN} if {@code null}
   */
  protected GenericMessage(final @Nonnull Collection<LocalizedMessage> messages,
      final @Nullable MessageMimeType mimeType) {
    Objects.requireNonNull(messages, "messages must not be null");
    if (messages.isEmpty()) {
      throw new IllegalArgumentException("messages must not be empty");
    }
    this.messages = List.copyOf(messages);
    if (this.messages.stream().filter(m -> m.language() == null).count() > 1) {
      throw new IllegalArgumentException("At most one message may be without a language");
    }
    final long languages = this.messages.stream()
        .map(LocalizedMessage::language)
        .filter(Objects::nonNull)
        .map(String::toLowerCase)
        .distinct()
        .count();
    if (languages != this.messages.stream().filter(m -> m.language() != null).count()) {
      throw new IllegalArgumentException("A language must not appear more than once among the messages");
    }
    this.mimeType = mimeType != null ? mimeType : MessageMimeType.TEXT_PLAIN;
  }

  /**
   * Gets the message in each of the languages it was given in. The list is never empty.
   *
   * @return the messages
   */
  public @Nonnull List<LocalizedMessage> getMessages() {
    return this.messages;
  }

  /**
   * Gets the MIME type of all the messages.
   *
   * @return the MIME type
   */
  public @Nonnull MessageMimeType getMimeType() {
    return this.mimeType;
  }

  /**
   * Gets the message that is not tied to a language. OpenID Connect allows one such message, SAML does not.
   *
   * @return the message without a language, or {@code null} if every message has a language
   */
  public @Nullable LocalizedMessage getDefaultMessage() {
    return this.messages.stream()
        .filter(m -> m.language() == null)
        .findFirst()
        .orElse(null);
  }

  /**
   * Gets the message to show for the supplied language. An exact match is preferred, then a message whose primary
   * language subtag is the same, and last the message that is not tied to a language.
   *
   * @param language the language tag, or {@code null} to ask for the message that is not tied to a language
   * @return the message, or {@code null} if there is nothing to show for the language
   */
  public @Nullable LocalizedMessage getMessage(final @Nullable String language) {
    if (language == null) {
      return this.getDefaultMessage();
    }
    for (final LocalizedMessage message : this.messages) {
      if (language.equalsIgnoreCase(message.language())) {
        return message;
      }
    }
    final int hyphen = language.indexOf('-');
    final String primary = hyphen > 0 ? language.substring(0, hyphen) : language;
    for (final LocalizedMessage message : this.messages) {
      if (primary.equalsIgnoreCase(message.getPrimaryLanguage())) {
        return message;
      }
    }
    return this.getDefaultMessage();
  }

  /** {@inheritDoc} */
  @Override
  public boolean equals(final Object obj) {
    if (this == obj) {
      return true;
    }
    if (obj == null || this.getClass() != obj.getClass()) {
      return false;
    }
    final GenericMessage other = (GenericMessage) obj;
    return Objects.equals(this.messages, other.messages) && this.mimeType == other.mimeType;
  }

  /** {@inheritDoc} */
  @Override
  public int hashCode() {
    return Objects.hash(this.messages, this.mimeType);
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return "mime-type=%s, languages=%s".formatted(this.mimeType,
        this.messages.stream().map(m -> m.language() != null ? m.language() : "none").toList());
  }

}
