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
package se.swedenconnect.spring.authnserver.oidc.authentication;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;

import java.io.Serial;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

import se.swedenconnect.spring.authnserver.LibraryVersion;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationRequirements;

/**
 * The authentication requirements of an OpenID Connect request. It adds what only OpenID Connect has: the scopes
 * that are honoured, {@code login_hint}, {@code ui_locales}, and the subject of a validated {@code id_token_hint}.
 * <p>
 * The login hint and the subject may be personal data, so {@link #toString()} does not include them.
 * </p>
 *
 * @author Martin Lindström
 */
public class OidcAuthenticationRequirements extends AuthenticationRequirements {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /** The requested scopes that the OpenID Provider offers. */
  private List<String> scopes = List.of();

  /** The login hint. */
  private String loginHint;

  /** The preferred languages of the user interface. */
  private List<String> uiLocales = List.of();

  /** The subject of the ID token given as {@code id_token_hint}. */
  private String idTokenHintSubject;

  /**
   * Default constructor.
   */
  public OidcAuthenticationRequirements() {
  }

  /**
   * Constructor setting up the OpenID Connect requirements from generic requirements.
   *
   * @param requirements the generic requirements
   */
  public OidcAuthenticationRequirements(final @Nonnull AuthenticationRequirements requirements) {
    super(requirements);
  }

  /**
   * Gets the requested scopes that the OpenID Provider offers. Other requested scopes are ignored.
   *
   * @return the scopes, possibly empty
   */
  public @Nonnull List<String> getScopes() {
    return this.scopes;
  }

  /**
   * Assigns the requested scopes that the OpenID Provider offers.
   *
   * @param scopes the scopes, may be {@code null}
   */
  public void setScopes(final @Nullable Collection<String> scopes) {
    this.scopes = scopes != null ? List.copyOf(scopes) : List.of();
  }

  /**
   * Gets the {@code login_hint}, a hint about the identifier the user may use to log in.
   *
   * @return the login hint, or {@code null}
   */
  public @Nullable String getLoginHint() {
    return this.loginHint;
  }

  /**
   * Assigns the login hint.
   *
   * @param loginHint the login hint, may be {@code null}
   */
  public void setLoginHint(final @Nullable String loginHint) {
    this.loginHint = loginHint;
  }

  /**
   * Gets the {@code ui_locales}, the preferred languages of the user interface as language tags, in order of
   * preference.
   *
   * @return the language tags, possibly empty
   */
  public @Nonnull List<String> getUiLocales() {
    return this.uiLocales;
  }

  /**
   * Assigns the preferred languages of the user interface.
   *
   * @param uiLocales the language tags, may be {@code null}
   */
  public void setUiLocales(final @Nullable Collection<String> uiLocales) {
    this.uiLocales = uiLocales != null ? List.copyOf(uiLocales) : List.of();
  }

  /**
   * Gets the subject ({@code sub}) of the ID token that the client passed as {@code id_token_hint}. The token has been
   * checked to be issued by this OpenID Provider for the client.
   *
   * @return the subject, or {@code null} if no hint was given
   */
  public @Nullable String getIdTokenHintSubject() {
    return this.idTokenHintSubject;
  }

  /**
   * Assigns the subject of the ID token given as {@code id_token_hint}.
   *
   * @param idTokenHintSubject the subject, may be {@code null}
   */
  public void setIdTokenHintSubject(final @Nullable String idTokenHintSubject) {
    this.idTokenHintSubject = idTokenHintSubject;
  }

  /** {@inheritDoc} */
  @Override
  public boolean equals(final Object obj) {
    if (!super.equals(obj)) {
      return false;
    }
    final OidcAuthenticationRequirements other = (OidcAuthenticationRequirements) obj;
    return Objects.equals(this.scopes, other.scopes)
        && Objects.equals(this.loginHint, other.loginHint)
        && Objects.equals(this.uiLocales, other.uiLocales)
        && Objects.equals(this.idTokenHintSubject, other.idTokenHintSubject);
  }

  /** {@inheritDoc} */
  @Override
  public int hashCode() {
    return Objects.hash(super.hashCode(), this.scopes, this.loginHint, this.uiLocales, this.idTokenHintSubject);
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    final StringBuilder sb = new StringBuilder(super.toString());
    if (!this.scopes.isEmpty()) {
      sb.append(", scopes=").append(this.scopes);
    }
    if (this.loginHint != null) {
      sb.append(", login-hint=<present>");
    }
    if (!this.uiLocales.isEmpty()) {
      sb.append(", ui-locales=").append(this.uiLocales);
    }
    if (this.idTokenHintSubject != null) {
      sb.append(", id-token-hint=<present>");
    }
    return sb.toString();
  }

}
