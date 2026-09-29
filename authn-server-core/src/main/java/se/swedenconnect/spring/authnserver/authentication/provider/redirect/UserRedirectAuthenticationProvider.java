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
package se.swedenconnect.spring.authnserver.authentication.provider.redirect;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;

import org.springframework.security.core.Authentication;

import se.swedenconnect.spring.authnserver.authentication.UserAuthentication;
import se.swedenconnect.spring.authnserver.authentication.provider.UserAuthenticationInputToken;
import se.swedenconnect.spring.authnserver.authentication.provider.UserAuthenticationProvider;
import se.swedenconnect.spring.authnserver.error.AuthenticationErrorException;

/**
 * A {@link UserAuthenticationProvider} that authenticates the user on pages of its own. Instead of a result it returns
 * a {@link RedirectForAuthenticationToken} that says where the user should be sent, and the flow continues when the
 * user comes back to {@link #getResumeAuthnPath()}.
 * <p>
 * A provider has one resume path, whichever protocol started the authentication. What is stored when the redirect
 * starts records the protocol, so the module's controller never has to know it.
 * </p>
 *
 * @author Martin Lindström
 * @see AbstractUserRedirectAuthenticationProvider
 */
public interface UserRedirectAuthenticationProvider extends UserAuthenticationProvider {

  /**
   * Continues the authentication when the user has returned to the resume path.
   *
   * @param token the resumed token, carrying the result or the error that the module's controller delivered
   * @return the authentication result
   * @throws AuthenticationErrorException if the authentication failed in a way that can be reported to the requester
   */
  @Nonnull
  UserAuthentication resumeAuthentication(@Nonnull final ResumedAuthenticationToken token)
      throws AuthenticationErrorException;

  /**
   * Predicate telling whether the provider can turn what the module's controller delivered into a
   * {@link UserAuthentication}. It is how the right provider is found when several of them are installed.
   *
   * @param authentication what the module's controller delivered, may be {@code null}
   * @return {@code true} if the provider can use it and {@code false} otherwise
   */
  boolean supportsUserAuthenticationToken(@Nullable final Authentication authentication);

  /**
   * Gets the side of the storage that the module's controller uses.
   *
   * @return a {@link RedirectAuthenticatorRepository}
   */
  @Nonnull
  RedirectAuthenticatorRepository getAuthenticatorRepository();

  /**
   * Gets the side of the storage that the protocol flow uses.
   *
   * @return a {@link RedirectFlowRepository}
   */
  @Nonnull
  RedirectFlowRepository getFlowRepository();

  /**
   * Gets the path that the user is sent to for authentication.
   *
   * @return the authentication path
   */
  @Nonnull
  String getAuthnPath();

  /**
   * Gets the path that the module sends the user back to when the authentication is done.
   *
   * @return the resume path
   */
  @Nonnull
  String getResumeAuthnPath();

  /**
   * Handles a {@link ResumedAuthenticationToken}, which continues an authentication, and a
   * {@link UserAuthenticationInputToken}, which starts one.
   */
  @Override
  default @Nullable Authentication authenticate(final @Nonnull Authentication authentication) {
    if (authentication instanceof final ResumedAuthenticationToken resumeToken) {
      if (!resumeToken.isError() && !this.supportsUserAuthenticationToken(resumeToken.getAuthnToken())) {
        return null;
      }
      return this.resumeAuthentication(resumeToken);
    }
    return UserAuthenticationProvider.super.authenticate(authentication);
  }

  /**
   * Supports {@link UserAuthenticationInputToken} and {@link ResumedAuthenticationToken}.
   */
  @Override
  default boolean supports(final @Nonnull Class<?> authentication) {
    return UserAuthenticationProvider.super.supports(authentication)
        || ResumedAuthenticationToken.class.isAssignableFrom(authentication);
  }

}
