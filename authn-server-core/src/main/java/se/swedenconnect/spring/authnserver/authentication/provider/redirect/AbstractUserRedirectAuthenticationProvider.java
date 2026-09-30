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

import java.util.Base64;
import java.util.List;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;

import se.swedenconnect.spring.authnserver.authentication.UserAuthentication;
import se.swedenconnect.spring.authnserver.authentication.provider.AbstractUserAuthenticationProvider;
import se.swedenconnect.spring.authnserver.authentication.provider.UserAuthenticationInputToken;
import se.swedenconnect.spring.authnserver.error.AuthenticationErrorException;

/**
 * Base class for a {@link UserRedirectAuthenticationProvider}. It keeps everything that
 * {@link AbstractUserAuthenticationProvider} does around an authentication, and replaces the authentication itself
 * with a redirect to the module's own pages.
 * <p>
 * The authentication contexts are still filtered, single sign-on is still decided, and a passive request that cannot
 * be answered still fails, all before the user is sent anywhere. When the user comes back, the result that the
 * module's controller delivered is run through the same post-authentication processing as a direct authentication.
 * </p>
 *
 * @author Martin Lindström
 */
public abstract class AbstractUserRedirectAuthenticationProvider extends AbstractUserAuthenticationProvider
    implements UserRedirectAuthenticationProvider {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(AbstractUserRedirectAuthenticationProvider.class);

  /** Generates the identifiers of the authentications, 32 random bytes each. */
  private static final StringKeyGenerator AUTHN_ID_GENERATOR =
      new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), 32);

  /** The path that the user is sent to for authentication. */
  private final String authnPath;

  /** The path that the module sends the user back to when the authentication is done. */
  private final String resumeAuthnPath;

  /** The storage of the authentications in progress. */
  private RedirectAuthenticationRepository repository = new SessionBasedRedirectAuthenticationRepository();

  /**
   * Constructor.
   *
   * @param authnPath the path that the user is sent to for authentication
   * @param resumeAuthnPath the path that the module sends the user back to when the authentication is done
   */
  protected AbstractUserRedirectAuthenticationProvider(final @NonNull String authnPath,
      final @NonNull String resumeAuthnPath) {
    this.authnPath = requirePath(authnPath, "authnPath");
    this.resumeAuthnPath = requirePath(resumeAuthnPath, "resumeAuthnPath");
  }

  /**
   * Gives the authentication an identifier and returns a {@link RedirectForAuthenticationToken} that sends the user to
   * {@link #getAuthnPath()}.
   */
  @Override
  protected @NonNull Authentication authenticate(final @NonNull UserAuthenticationInputToken token,
      final @NonNull List<String> authnContextUris) throws AuthenticationErrorException {

    final RedirectForAuthenticationToken redirectToken = new RedirectForAuthenticationToken(this.generateAuthnId(),
        token, authnContextUris, this.authnPath, this.resumeAuthnPath);
    log.debug("Provider '{}' redirects to '{}' for authentication [{}]", this.getName(), this.authnPath,
        token.getLogString());
    return redirectToken;
  }

  /**
   * Throws the error that the module's controller reported, or turns what it delivered into a
   * {@link UserAuthentication} and runs the post-authentication processing on it.
   */
  @Override
  public @NonNull UserAuthentication resumeAuthentication(final @NonNull ResumedAuthenticationToken token)
      throws AuthenticationErrorException {

    Objects.requireNonNull(token, "token must not be null");
    final UserAuthenticationInputToken inputToken = token.getAuthnInputToken();

    final AuthenticationErrorException error = token.getError();
    if (error != null) {
      log.info("Authentication by provider '{}' failed: {} - {} [{}]", this.getName(), error.getError(),
          error.getDescription(), inputToken.getLogString());
      throw error;
    }

    final UserAuthentication authentication = this.createUserAuthentication(token);
    this.completeResult(authentication, inputToken);
    log.debug("Provider '{}' resumed the authentication of '{}' [{}]", this.getName(), authentication.getName(),
        inputToken.getLogString());
    return authentication;
  }

  /**
   * Turns what the module's controller delivered into a {@link UserAuthentication}. A controller that already delivers
   * a {@link UserAuthentication} has nothing to do here but cast; one that delivers a token of its own builds the
   * result from it.
   * <p>
   * The method is called only for an authentication that succeeded, and only when
   * {@link #supportsUserAuthenticationToken(Authentication)} accepted what the controller delivered.
   * </p>
   *
   * @param token the resumed token
   * @return the authentication result
   * @throws AuthenticationErrorException if the result cannot be used
   */
  protected abstract @NonNull UserAuthentication createUserAuthentication(
      final @NonNull ResumedAuthenticationToken token)
      throws AuthenticationErrorException;

  /**
   * Generates the identifier of an authentication. It is unguessable, since it is what ties the user's visit to the
   * module's pages to the authentication that is in progress.
   *
   * @return an identifier
   */
  protected @NonNull String generateAuthnId() {
    return AUTHN_ID_GENERATOR.generateKey();
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull RedirectAuthenticatorRepository getAuthenticatorRepository() {
    return this.repository;
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull RedirectFlowRepository getFlowRepository() {
    return this.repository;
  }

  /**
   * Assigns the storage of the authentications in progress. It defaults to
   * {@link SessionBasedRedirectAuthenticationRepository}.
   *
   * @param repository the storage
   */
  public void setRepository(final @NonNull RedirectAuthenticationRepository repository) {
    this.repository = Objects.requireNonNull(repository, "repository must not be null");
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull String getAuthnPath() {
    return this.authnPath;
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull String getResumeAuthnPath() {
    return this.resumeAuthnPath;
  }

  /**
   * Asserts that a path is set, begins with a {@code '/'} and carries no query string.
   *
   * @param path the path to check
   * @param name the name of the path, for the error message
   * @return the trimmed path
   */
  private static @NonNull String requirePath(final String path, final @NonNull String name) {
    final String trimmed = path != null ? path.trim() : "";
    if (!trimmed.startsWith("/") || trimmed.indexOf('?') >= 0) {
      throw new IllegalArgumentException(name + " must be set, begin with a '/' and carry no query string");
    }
    return trimmed;
  }

}
