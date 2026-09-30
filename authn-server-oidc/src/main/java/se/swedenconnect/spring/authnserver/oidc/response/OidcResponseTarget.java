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
package se.swedenconnect.spring.authnserver.oidc.response;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import jakarta.servlet.http.HttpServletRequest;

import java.io.Serial;
import java.io.Serializable;
import java.util.Objects;

import com.nimbusds.oauth2.sdk.ResponseMode;

import se.swedenconnect.spring.authnserver.LibraryVersion;

/**
 * Where and how the OpenID Provider answers an authentication request: the client, the redirect URI, the response
 * mode and the {@code state}.
 * <p>
 * The target is established during the processing of the authentication request, once the client and the redirect
 * URI are known. From then on, a failure is answered with an error response. It is kept as an attribute of the HTTP
 * request, see {@link #setOnRequest(HttpServletRequest, OidcResponseTarget)}.
 * </p>
 *
 * @param clientId the {@code client_id} of the client
 * @param redirectUri the redirect URI, registered for the client
 * @param responseMode the response mode, {@code query} or {@code form_post}
 * @param state the {@code state} of the request, or {@code null} if the request had none
 * @author Martin Lindström
 */
public record OidcResponseTarget(@Nonnull String clientId, @Nonnull String redirectUri,
    @Nonnull String responseMode, @Nullable String state) implements Serializable {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /** The name of the request attribute holding the response target. */
  public static final String REQUEST_ATTRIBUTE = OidcResponseTarget.class.getName();

  /**
   * Constructor.
   *
   * @param clientId the {@code client_id} of the client
   * @param redirectUri the redirect URI
   * @param responseMode the response mode
   * @param state the {@code state}, or {@code null}
   */
  public OidcResponseTarget {
    Objects.requireNonNull(clientId, "clientId must not be null");
    Objects.requireNonNull(redirectUri, "redirectUri must not be null");
    Objects.requireNonNull(responseMode, "responseMode must not be null");
  }

  /**
   * Tells whether the response is posted to the client ({@code form_post}).
   *
   * @return {@code true} for {@code form_post} and {@code false} for {@code query}
   */
  public boolean isFormPost() {
    return ResponseMode.FORM_POST.getValue().equals(this.responseMode);
  }

  /**
   * Keeps the response target as an attribute of the HTTP request.
   *
   * @param request the HTTP request
   * @param target the response target
   */
  public static void setOnRequest(final @Nonnull HttpServletRequest request, final @Nonnull OidcResponseTarget target) {
    request.setAttribute(REQUEST_ATTRIBUTE, target);
  }

  /**
   * Gets the response target that is kept as an attribute of the HTTP request.
   *
   * @param request the HTTP request
   * @return the response target, or {@code null} if none has been established
   */
  public static @Nullable OidcResponseTarget fromRequest(final @Nonnull HttpServletRequest request) {
    return request.getAttribute(REQUEST_ATTRIBUTE) instanceof final OidcResponseTarget target ? target : null;
  }

}
