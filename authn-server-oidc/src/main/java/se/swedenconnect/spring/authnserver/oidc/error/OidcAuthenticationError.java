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
package se.swedenconnect.spring.authnserver.oidc.error;

import org.jspecify.annotations.NonNull;

import com.nimbusds.oauth2.sdk.ErrorObject;

import se.swedenconnect.spring.authnserver.error.AuthenticationError;

/**
 * An {@link AuthenticationError} of the application that is reported to an OpenID Connect Relying Party with an error
 * of its own. An error of the application that does not implement this interface is reported with
 * {@code access_denied}.
 * <p>
 * The error code must be one that the authorization endpoint may return, see {@link OidcErrorMapping}. The
 * {@code error_description} is the description of the {@code AuthenticationErrorException}, not the description of the
 * returned error.
 * </p>
 *
 * @author Martin Lindström
 */
public interface OidcAuthenticationError extends AuthenticationError {

  /**
   * Gets the OAuth 2.0 error that the error is reported with.
   *
   * @return an {@link ErrorObject}
   */
  @NonNull ErrorObject getOidcError();

}
