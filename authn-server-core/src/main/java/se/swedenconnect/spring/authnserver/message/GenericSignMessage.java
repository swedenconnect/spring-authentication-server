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
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.util.StringUtils;

import se.swedenconnect.spring.authnserver.LibraryVersion;

/**
 * A message that the user must be shown before approving a signature.
 * <p>
 * It is the protocol-neutral form of the SAML {@code SignMessage} extension and of the {@code sign_message} field of
 * the OpenID Connect {@code https://id.oidc.se/param/signRequest} request parameter. A SAML sign message holds a single
 * message without a language, an OpenID Connect sign message may hold several languages.
 * </p>
 * <p>
 * An encrypted SAML sign message is decrypted before this object is built, and the SAML {@code DisplayEntity} is
 * checked by the SAML layer and is not carried here.
 * </p>
 *
 * @author Martin Lindström
 */
public class GenericSignMessage extends GenericMessage {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /** Whether the message must be shown to the user. */
  private final boolean mustShow;

  /** The Base64 encoding of the data to be signed. */
  private final String tbsData;

  /**
   * Constructor.
   *
   * @param messages the message in each of the languages it was given in, must not be empty
   * @param mimeType the MIME type of all the messages, {@link MessageMimeType#TEXT_PLAIN} if {@code null}
   * @param mustShow whether the message must be shown to the user. SAML states this in {@code MustShow}, OpenID Connect
   *          always requires the message to be shown
   * @param tbsData the Base64 encoding of the data to be signed, may be {@code null}. Only the OpenID Connect signing
   *          case carries it
   */
  public GenericSignMessage(final @NonNull Collection<LocalizedMessage> messages,
      final @Nullable MessageMimeType mimeType, final boolean mustShow, final @Nullable String tbsData) {
    super(messages, mimeType);
    this.mustShow = mustShow;
    if (tbsData != null) {
      if (!StringUtils.hasText(tbsData)) {
        throw new IllegalArgumentException("tbsData must not be empty");
      }
      try {
        Base64.getDecoder().decode(tbsData);
      }
      catch (final IllegalArgumentException e) {
        throw new IllegalArgumentException("tbsData must be Base64 encoded", e);
      }
    }
    this.tbsData = tbsData;
  }

  /**
   * Creates a plain text sign message in one language that must be shown to the user.
   *
   * @param language the language tag, or {@code null}
   * @param text the message text
   * @return a {@link GenericSignMessage}
   */
  public static @NonNull GenericSignMessage ofText(final @Nullable String language, final @NonNull String text) {
    return new GenericSignMessage(List.of(LocalizedMessage.ofText(language, text)), MessageMimeType.TEXT_PLAIN, true,
        null);
  }

  /**
   * Predicate telling whether the message must be shown to the user. If it must and it cannot be, the operation is
   * rejected.
   *
   * @return {@code true} if the message must be shown and {@code false} otherwise
   */
  public boolean isMustShow() {
    return this.mustShow;
  }

  /**
   * Gets the Base64 encoding of the data to be signed. Only the OpenID Connect signing case carries it.
   *
   * @return the data to be signed, or {@code null} if it is not present
   */
  public @Nullable String getTbsData() {
    return this.tbsData;
  }

  /**
   * Gets the data to be signed in decoded form.
   *
   * @return the data to be signed, or {@code null} if it is not present
   */
  public byte @Nullable [] getTbsDataBytes() {
    return this.tbsData != null ? Base64.getDecoder().decode(this.tbsData) : null;
  }

  /** {@inheritDoc} */
  @Override
  public boolean equals(final Object obj) {
    if (!super.equals(obj)) {
      return false;
    }
    final GenericSignMessage other = (GenericSignMessage) obj;
    return this.mustShow == other.mustShow && Objects.equals(this.tbsData, other.tbsData);
  }

  /** {@inheritDoc} */
  @Override
  public int hashCode() {
    return Objects.hash(super.hashCode(), this.mustShow, this.tbsData);
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return "sign-message: %s, must-show=%s%s".formatted(super.toString(), this.mustShow,
        this.tbsData != null ? ", tbs-data=" + this.tbsData : "");
  }

}
