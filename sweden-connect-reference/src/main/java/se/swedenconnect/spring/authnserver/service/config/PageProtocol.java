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
package se.swedenconnect.spring.authnserver.service.config;

import java.util.Locale;
import java.util.Objects;

import org.jspecify.annotations.NonNull;

import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;

/**
 * Tells the pages the protocol of the authentication in progress, so that the heading, the browser title and the help
 * title name an Identity Provider for SAML and an OpenID Provider for OpenID Connect.
 * <p>
 * The page model gets the protocol as {@value #MODEL_ATTRIBUTE}, {@code saml} or {@code oidc}, and the templates pick
 * the message key with that suffix, for example {@code idp.msg.heading.oidc}. A page without the attribute uses the
 * key without a suffix, which holds a neutral text.
 * </p>
 *
 * @author Martin Lindström
 */
public final class PageProtocol {

  /** The name of the model attribute holding the protocol. */
  public static final String MODEL_ATTRIBUTE = "protocol";

  /**
   * Gets the value of the model attribute for a protocol.
   *
   * @param protocol the protocol of the authentication in progress
   * @return {@code saml} or {@code oidc}
   */
  public static @NonNull String value(final @NonNull AuthenticationProtocol protocol) {
    return Objects.requireNonNull(protocol, "protocol must not be null").name().toLowerCase(Locale.ROOT);
  }

  // Hidden constructor.
  private PageProtocol() {
  }

}
