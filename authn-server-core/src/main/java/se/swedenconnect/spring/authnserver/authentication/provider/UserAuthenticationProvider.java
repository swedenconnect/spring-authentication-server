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
package se.swedenconnect.spring.authnserver.authentication.provider;

import java.util.List;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;

import se.swedenconnect.spring.authnserver.authentication.UserAuthentication;
import se.swedenconnect.spring.authnserver.error.AuthenticationErrorException;

/**
 * What an authentication module implements. It is a Spring Security {@link AuthenticationProvider} that takes a
 * {@link UserAuthenticationInputToken} and authenticates the user.
 * <p>
 * A provider releases everything it knows about the user. The protocol module decides what is actually sent to the
 * requester. A provider that filtered the attributes itself would make its result useless for single sign-on, since the
 * next requester may ask for another set.
 * </p>
 * <p>
 * Several providers may be installed. A provider that cannot deliver any of the requested authentication contexts says
 * so by returning {@code null}, and the next provider is asked.
 * </p>
 *
 * @author Martin Lindström
 * @see AbstractUserAuthenticationProvider
 */
public interface UserAuthenticationProvider extends AuthenticationProvider {

  /**
   * Gets the name of the provider, used in logs and to tell providers apart.
   *
   * @return the name of the provider
   */
  @NonNull String getName();

  /**
   * Gets the authentication contexts that the provider can deliver.
   *
   * @return the supported authentication context URIs
   */
  @NonNull List<String> getSupportedAuthnContextUris();

  /**
   * Gets the SAML entity categories that the provider declares. The SAML Identity Provider publishes them in its
   * metadata. Other protocols do not use them. The default is none.
   *
   * @return entity category URIs
   */
  default @NonNull List<String> getEntityCategories() {
    return List.of();
  }

  /**
   * Gets the generic attributes that the provider can deliver, given by their identifiers, for example
   * {@code attribute.personal-identity-number}. The OpenID Provider maps them to the claims that it declares as
   * supported, and derives its scopes from them unless the provider declares its scopes. The default is none.
   *
   * @return attribute identifiers
   */
  default @NonNull List<String> getSupportedAttributes() {
    return List.of();
  }

  /**
   * Gets the OpenID Connect scopes that the provider offers. When the provider declares scopes, the OpenID Provider
   * offers exactly those for it. When it declares none, the scopes are derived from the claims of
   * {@link #getSupportedAttributes()}. Other protocols do not use them. The default is none.
   *
   * @return scope values
   */
  default @NonNull List<String> getSupportedScopes() {
    return List.of();
  }

  /**
   * Authenticates the user.
   * <p>
   * The result is normally a {@link UserAuthentication}. It is {@code null}, and only {@code null}, when the provider
   * cannot deliver any of the requested authentication contexts, so that another provider may take the request. A
   * provider that sends the user somewhere to authenticate returns the token of that flow instead.
   * </p>
   *
   * @param token what the provider is given
   * @return the authentication, or {@code null} if the provider does not handle the request
   * @throws AuthenticationErrorException if the authentication fails in a way that can be reported to the requester
   */
  @Nullable Authentication authenticateUser(final @NonNull UserAuthenticationInputToken token)
      throws AuthenticationErrorException;

  /**
   * Maps to {@link #authenticateUser(UserAuthenticationInputToken)}.
   */
  @Override
  default @Nullable Authentication authenticate(final @NonNull Authentication authentication) {
    if (!(authentication instanceof final UserAuthenticationInputToken token)) {
      return null;
    }
    return this.authenticateUser(token);
  }

  /**
   * Supports {@link UserAuthenticationInputToken}.
   */
  @Override
  default boolean supports(final @NonNull Class<?> authentication) {
    return UserAuthenticationInputToken.class.isAssignableFrom(authentication);
  }

}
