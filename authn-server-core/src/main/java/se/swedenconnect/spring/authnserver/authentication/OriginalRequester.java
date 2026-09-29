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
package se.swedenconnect.spring.authnserver.authentication;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;

import java.io.Serial;
import java.io.Serializable;
import java.util.Objects;

import org.springframework.util.StringUtils;

import se.swedenconnect.spring.authnserver.LibraryVersion;

/**
 * The party that originally asked for the authentication, passed on by a requester that acts as a proxy.
 * <p>
 * SAML carries this as {@code <saml2p:RequesterID>} under {@code <saml2p:Scoping>}, which may appear any number of
 * times and holds no token. OpenID Connect carries it as {@code originalClientId}, with an optional
 * {@code originalClientToken}, and allows only one.
 * </p>
 *
 * @param identifier the identifier of the original requester
 * @param token a token holding information about the original requester, Base64 encoded. The format is not defined by
 *          any specification. Only OpenID Connect carries it
 * @author Martin Lindström
 */
public record OriginalRequester(@Nonnull String identifier, @Nullable String token) implements Serializable {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /**
   * Constructor.
   *
   * @param identifier the identifier of the original requester
   * @param token a token holding information about the original requester, may be {@code null}
   */
  public OriginalRequester {
    Objects.requireNonNull(identifier, "identifier must not be null");
    if (!StringUtils.hasText(identifier)) {
      throw new IllegalArgumentException("identifier must not be empty");
    }
  }

  /**
   * Creates an original requester without a token.
   *
   * @param identifier the identifier of the original requester
   * @return an {@link OriginalRequester}
   */
  public static @Nonnull OriginalRequester of(final @Nonnull String identifier) {
    return new OriginalRequester(identifier, null);
  }

}
