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

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.util.StringUtils;

/**
 * The MIME types that a user message or a sign message may use.
 *
 * @author Martin Lindström
 */
public enum MessageMimeType {

  /** Plain text, always UTF-8. SAML uses {@code text} for this type. */
  TEXT_PLAIN("text/plain"),

  /** Markdown. */
  TEXT_MARKDOWN("text/markdown"),

  /** HTML. Only the SAML sign message uses this type. */
  TEXT_HTML("text/html");

  /** The SAML sign message spelling of {@link #TEXT_PLAIN}. */
  public static final String SAML_TEXT = "text";

  /** The MIME type. */
  private final String mimeType;

  /**
   * Constructor.
   *
   * @param mimeType the MIME type
   */
  MessageMimeType(final String mimeType) {
    this.mimeType = mimeType;
  }

  /**
   * Gets the MIME type.
   *
   * @return the MIME type
   */
  public @NonNull String getMimeType() {
    return this.mimeType;
  }

  /**
   * Parses a MIME type. The SAML sign message spelling {@value #SAML_TEXT} is accepted for {@link #TEXT_PLAIN}, and any
   * parameters, such as {@code ;charset=UTF-8}, are ignored. Both specifications state that {@code text/plain} is
   * assumed when no MIME type is given, so that is what a missing value gives.
   *
   * @param mimeType the MIME type, may be {@code null}
   * @return a {@link MessageMimeType}
   * @throws IllegalArgumentException if the MIME type is not supported
   */
  public static @NonNull MessageMimeType parse(final @Nullable String mimeType) {
    if (!StringUtils.hasText(mimeType)) {
      return TEXT_PLAIN;
    }
    final String type = mimeType.split(";")[0].trim().toLowerCase();
    if (SAML_TEXT.equals(type)) {
      return TEXT_PLAIN;
    }
    for (final MessageMimeType candidate : values()) {
      if (candidate.mimeType.equals(type)) {
        return candidate;
      }
    }
    throw new IllegalArgumentException("Unsupported message MIME type: " + mimeType);
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return this.mimeType;
  }

}
