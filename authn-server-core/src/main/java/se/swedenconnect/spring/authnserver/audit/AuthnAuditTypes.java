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

import se.swedenconnect.spring.audit.AuditType;

/**
 * The types of the audit events that the authentication server produces.
 *
 * @author Martin Lindström
 */
public final class AuthnAuditTypes {

  /** A request has arrived, before any check. */
  public static final AuditType AUTHN_REQUEST_RECEIVED = AuditType.of("authn_request_received");

  /** The request passed all checks and user authentication starts. */
  public static final AuditType AUTHN_REQUEST_ACCEPTED = AuditType.of("authn_request_accepted");

  /** The user authenticated, or single sign-on was used. */
  public static final AuditType AUTHN_USER_AUTHENTICATED = AuditType.of("authn_user_authenticated");

  /** OpenID Connect only: the authorization response with the code is sent. */
  public static final AuditType AUTHN_AUTHORIZATION_RESPONSE = AuditType.of("authn_authorization_response");

  /** A SAML response is sent, or an OpenID Connect ID token is issued. */
  public static final AuditType AUTHN_SUCCESS_RESPONSE = AuditType.of("authn_success_response");

  /** OpenID Connect only: a UserInfo response is sent. */
  public static final AuditType AUTHN_USERINFO_DELIVERED = AuditType.of("authn_userinfo_delivered");

  /** An error is sent to a requester. */
  public static final AuditType AUTHN_ERROR_RESPONSE = AuditType.of("authn_error_response");

  /** An error is shown to the user, since no response can be sent to the requester. */
  public static final AuditType AUTHN_UNRECOVERABLE_ERROR = AuditType.of("authn_unrecoverable_error");

  /** A monitored credential failed its test. */
  public static final AuditType AUTHN_CREDENTIAL_TEST_ERROR = AuditType.of("authn_credential_test_error");

  /** A monitored credential that failed its test was reloaded. */
  public static final AuditType AUTHN_CREDENTIAL_RELOAD_SUCCESS = AuditType.of("authn_credential_reload_success");

  /** A monitored credential that failed its test could not be reloaded. */
  public static final AuditType AUTHN_CREDENTIAL_RELOAD_ERROR = AuditType.of("authn_credential_reload_error");

  // Hidden constructor
  private AuthnAuditTypes() {
  }

}
