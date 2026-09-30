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

import jakarta.servlet.http.HttpServletRequest;

import java.io.Serial;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.StringUtils;

import se.swedenconnect.spring.authnserver.LibraryVersion;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.authentication.provider.UserAuthenticationInputToken;

/**
 * What a {@link UserRedirectAuthenticationProvider} returns instead of a result: an order to send the user to the
 * module's own pages. It carries the identifier of the authentication, what the provider was given, and the paths out
 * and back.
 * <p>
 * The token is stored while the user is away, so it survives Java serialization.
 * </p>
 *
 * @author Martin Lindström
 * @see AbstractUserRedirectAuthenticationProvider
 */
public class RedirectForAuthenticationToken implements Authentication {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /**
   * The name of the request parameter that carries the identifier of the authentication, out to the module's pages and
   * back to the resume path.
   */
  public static final String AUTHN_ID_PARAMETER = "authnId";

  /** The identifier of this authentication. */
  private final String authnId;

  /** What the provider was given. */
  private final UserAuthenticationInputToken authnInputToken;

  /** The authentication contexts that may be used, in the requester's order of preference. */
  private final List<String> authnContextUris;

  /** The path that the user is sent to for authentication. */
  private final String authnPath;

  /** The path that the module sends the user back to when the authentication is done. */
  private final String resumeAuthnPath;

  /**
   * Constructor.
   *
   * @param authnId the identifier of this authentication
   * @param authnInputToken what the provider was given
   * @param authnContextUris the authentication contexts that may be used, in the requester's order of preference
   * @param authnPath the path that the user is sent to for authentication
   * @param resumeAuthnPath the path that the module sends the user back to when the authentication is done
   */
  public RedirectForAuthenticationToken(final @NonNull String authnId,
      final @NonNull UserAuthenticationInputToken authnInputToken,
      final @Nullable Collection<String> authnContextUris, final @NonNull String authnPath,
      final @NonNull String resumeAuthnPath) {
    this.authnId = requireId(authnId);
    this.authnInputToken = Objects.requireNonNull(authnInputToken, "authnInputToken must not be null");
    this.authnContextUris = authnContextUris != null ? List.copyOf(authnContextUris) : List.of();
    this.authnPath = requirePath(authnPath, "authnPath");
    this.resumeAuthnPath = requirePath(resumeAuthnPath, "resumeAuthnPath");
  }

  /**
   * Gets the identifier of this authentication. It is unguessable, it is carried to the module's pages and back to the
   * resume path, and it is what tells several authentications in the same session apart.
   *
   * @return the identifier of the authentication
   */
  public @NonNull String getAuthnId() {
    return this.authnId;
  }

  /**
   * Gets the protocol that the authentication was started for.
   *
   * @return the protocol
   */
  public @NonNull AuthenticationProtocol getProtocol() {
    return this.authnInputToken.getRequester().protocol();
  }

  /**
   * Gets what the provider was given.
   *
   * @return the authentication input token
   */
  public @NonNull UserAuthenticationInputToken getAuthnInputToken() {
    return this.authnInputToken;
  }

  /**
   * Gets the authentication contexts that may be used, in the requester's order of preference. They are the requested
   * contexts that the provider supports, the same list that a provider that authenticates directly is given.
   *
   * @return the authentication context URIs, possibly empty
   */
  public @NonNull List<String> getAuthnContextUris() {
    return this.authnContextUris;
  }

  /**
   * Gets the path that the user is sent to for authentication.
   *
   * @return the authentication path
   */
  public @NonNull String getAuthnPath() {
    return this.authnPath;
  }

  /**
   * Gets the path that the module sends the user back to when the authentication is done.
   *
   * @return the resume path
   */
  public @NonNull String getResumeAuthnPath() {
    return this.resumeAuthnPath;
  }

  /**
   * Gets the authentication path with the identifier of the authentication appended. It is where the user is sent.
   *
   * @return the path to redirect to
   */
  public @NonNull String getRedirectPath() {
    return pathWithAuthnId(this.authnPath, this.authnId);
  }

  /**
   * Gets the resume path with the identifier of the authentication appended. It is where the module sends the user
   * when the authentication is done.
   *
   * @return the path to redirect to
   */
  public @NonNull String getResumeRedirectPath() {
    return pathWithAuthnId(this.resumeAuthnPath, this.authnId);
  }

  /**
   * Appends the identifier of an authentication to a path, as the {@value #AUTHN_ID_PARAMETER} request parameter.
   *
   * @param path the path, which must not already carry a query string
   * @param authnId the identifier of the authentication
   * @return the path with the identifier appended
   */
  public static @NonNull String pathWithAuthnId(final @NonNull String path, final @NonNull String authnId) {
    return "%s?%s=%s".formatted(requirePath(path, "path"), AUTHN_ID_PARAMETER,
        URLEncoder.encode(requireId(authnId), StandardCharsets.UTF_8));
  }

  /**
   * Gets the identifier of the authentication that a request concerns, from its {@value #AUTHN_ID_PARAMETER} request
   * parameter.
   *
   * @param request the HTTP servlet request
   * @return the identifier of the authentication, or {@code null} if the request does not carry one
   */
  public static @Nullable String getAuthnId(final @NonNull HttpServletRequest request) {
    final String authnId = Objects.requireNonNull(request, "request must not be null")
        .getParameter(AUTHN_ID_PARAMETER);
    return StringUtils.hasText(authnId) ? authnId : null;
  }

  /**
   * Maps to the name of the authentication input token.
   */
  @Override
  public @NonNull String getName() {
    return this.authnInputToken.getName();
  }

  /**
   * Always returns an empty list.
   */
  @Override
  public @NonNull Collection<? extends GrantedAuthority> getAuthorities() {
    return List.of();
  }

  /**
   * Maps to the credentials of the authentication input token.
   */
  @Override
  public @Nullable Object getCredentials() {
    return this.authnInputToken.getCredentials();
  }

  /**
   * Maps to the details of the authentication input token.
   */
  @Override
  public @Nullable Object getDetails() {
    return this.authnInputToken.getDetails();
  }

  /**
   * Maps to the principal of the authentication input token.
   */
  @Override
  public @NonNull Object getPrincipal() {
    return this.authnInputToken.getPrincipal();
  }

  /**
   * Always returns {@code false}, since the user has not been authenticated yet.
   */
  @Override
  public boolean isAuthenticated() {
    return false;
  }

  /**
   * Must not be called, and throws {@link IllegalArgumentException}.
   */
  @Override
  public void setAuthenticated(final boolean isAuthenticated) throws IllegalArgumentException {
    throw new IllegalArgumentException(
        "setAuthenticated on " + this.getClass().getSimpleName() + " must not be called");
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull String toString() {
    return "authn-id: '%s', %s".formatted(this.authnId, this.authnInputToken.getLogString());
  }

  /**
   * Asserts that a path is set, begins with a {@code '/'} and carries no query string.
   *
   * @param path the path to check
   * @param name the name of the path, for the error message
   * @return the trimmed path
   */
  private static @NonNull String requirePath(final @Nullable String path, final @NonNull String name) {
    final String trimmed = path != null ? path.trim() : "";
    if (!trimmed.startsWith("/") || trimmed.indexOf('?') >= 0) {
      throw new IllegalArgumentException(name + " must be set, begin with a '/' and carry no query string");
    }
    return trimmed;
  }

  /**
   * Asserts that an identifier is set.
   *
   * @param authnId the identifier to check
   * @return the identifier
   */
  private static @NonNull String requireId(final @Nullable String authnId) {
    if (!StringUtils.hasText(authnId)) {
      throw new IllegalArgumentException("authnId must be set");
    }
    return authnId;
  }

}
