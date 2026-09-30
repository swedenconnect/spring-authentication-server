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
package se.swedenconnect.spring.authnserver.saml.error;

import org.jspecify.annotations.NonNull;

import se.swedenconnect.spring.authnserver.error.UnrecoverableError;

/**
 * The errors of the SAML Identity Provider that cannot be reported to the Service Provider, because it is not known who
 * sent the request or where to send the response. They end in an error at the Identity Provider.
 *
 * @author Martin Lindström
 */
public enum SamlUnrecoverableError implements UnrecoverableError {

  /** The received message could not be decoded. */
  FAILED_DECODE("authn-server.error.saml.unrecoverable.decode",
      "The received message could not be decoded into a valid authentication request"),

  /** The authentication request has an invalid format. */
  INVALID_AUTHNREQUEST_FORMAT("authn-server.error.saml.unrecoverable.format",
      "The format of the received authentication request is invalid"),

  /** The endpoint of the message does not match where it was received. */
  ENDPOINT_CHECK_FAILURE("authn-server.error.saml.unrecoverable.endpoint",
      "The endpoint information supplied in the authentication request does not correspond with the endpoint on which "
          + "the message was delivered"),

  /** The message is too old. */
  MESSAGE_TOO_OLD("authn-server.error.saml.unrecoverable.too-old", "The received message is too old"),

  /** The sender of the request is not known. */
  UNKNOWN_PEER("authn-server.error.saml.unrecoverable.unknown-peer",
      "The sender of the authentication request has not been registered at the Identity Provider"),

  /** The sender of the request could not be looked up, since the client registry failed. */
  PEER_LOOKUP_FAILED("authn-server.error.saml.unrecoverable.peer-lookup-failed",
      "The sender of the authentication request could not be looked up"),

  /** The request has already been processed. */
  REPLAY_DETECTED("authn-server.error.saml.unrecoverable.replay",
      "The authentication request has already been processed"),

  /** No valid assertion consumer service could be found. */
  INVALID_ASSERTION_CONSUMER_SERVICE("authn-server.error.saml.unrecoverable.acs",
      "The indicated Assertion Consumer Service is not registered"),

  /** The request is not signed, but must be. */
  MISSING_AUTHNREQUEST_SIGNATURE("authn-server.error.saml.unrecoverable.no-signature",
      "The authentication request was not signed, which is required"),

  /** The signature of the request is not valid. */
  INVALID_AUTHNREQUEST_SIGNATURE("authn-server.error.saml.unrecoverable.bad-signature",
      "Signature validation of the received authentication request failed");

  /** The message code. */
  private final String messageCode;

  /** The description. */
  private final String description;

  /**
   * Constructor.
   *
   * @param messageCode the message code
   * @param description the description
   */
  SamlUnrecoverableError(final String messageCode, final String description) {
    this.messageCode = messageCode;
    this.description = description;
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull String getMessageCode() {
    return this.messageCode;
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull String getDescription() {
    return this.description;
  }

}
