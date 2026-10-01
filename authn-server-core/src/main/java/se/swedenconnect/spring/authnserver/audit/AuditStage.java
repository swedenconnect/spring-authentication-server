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
package se.swedenconnect.spring.authnserver.audit;

import org.jspecify.annotations.NonNull;

/**
 * The stage of the processing that an error came from.
 *
 * @author Martin Lindström
 */
public enum AuditStage {

  /** The processing of the authentication request, before user authentication starts. */
  AUTHN_REQUEST("authn_request"),

  /** The user authentication, including the return from an authentication module's own pages. */
  USER_AUTHENTICATION("user_authentication"),

  /** The completion of the response once the user has been authenticated, such as the release of attributes. */
  RESPONSE("response"),

  /** OpenID Connect only: the token endpoint. */
  TOKEN("token"),

  /** OpenID Connect only: the UserInfo endpoint. */
  USERINFO("userinfo");

  /** The value written to the audit event. */
  private final String value;

  /**
   * Constructor.
   *
   * @param value the value written to the audit event
   */
  AuditStage(final String value) {
    this.value = value;
  }

  /**
   * Gets the value written to the audit event.
   *
   * @return the value
   */
  public @NonNull String getValue() {
    return this.value;
  }

}
