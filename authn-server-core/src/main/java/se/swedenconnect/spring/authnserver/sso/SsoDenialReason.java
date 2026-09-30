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
package se.swedenconnect.spring.authnserver.sso;

import org.jspecify.annotations.NonNull;

/**
 * Why a previous authentication was not reused. The reason is carried in the refusal so that it can be logged, and so
 * that a requester that asked for a passive authentication gets the error its protocol expects, see
 * {@link SsoDenialKind}.
 *
 * @author Martin Lindström
 */
public enum SsoDenialReason {

  /** There is no previous authentication to reuse. */
  NO_PREVIOUS_AUTHENTICATION(SsoDenialKind.LOGIN_REQUIRED, "There is no previous authentication"),

  /** The previous authentication may not be reused, for example because a sign message was displayed. */
  NOT_REUSABLE(SsoDenialKind.LOGIN_REQUIRED, "The previous authentication may not be reused"),

  /** The requester asked for the user to be authenticated again. */
  FORCE_AUTHN(SsoDenialKind.LOGIN_REQUIRED, "The requester asked for a new authentication"),

  /** The previous authentication is older than the maximum authentication age that the requester accepts. */
  MAX_AUTHN_AGE_EXCEEDED(SsoDenialKind.LOGIN_REQUIRED,
      "The previous authentication is older than the requested maximum authentication age"),

  /** The previous authentication is older than the single sign-on policy allows. */
  TIME_LIMIT_EXCEEDED(SsoDenialKind.LOGIN_REQUIRED,
      "The previous authentication is older than the single sign-on policy allows"),

  /** The request carries a sign message, and a signature is always approved by the user. */
  SIGN_MESSAGE(SsoDenialKind.LOGIN_REQUIRED, "The request carries a sign message"),

  /** The previous authentication was made for another requester. */
  OTHER_REQUESTER(SsoDenialKind.LOGIN_REQUIRED, "The previous authentication was made for another requester"),

  /** The previous authentication was made under another authentication context. */
  OTHER_AUTHN_CONTEXT(SsoDenialKind.LOGIN_REQUIRED,
      "The previous authentication was made under another authentication context"),

  /** An attribute value that the requester asked for does not match the value the user has. */
  ATTRIBUTE_VALUE_MISMATCH(SsoDenialKind.LOGIN_REQUIRED,
      "A requested attribute value does not match the value of the authenticated user"),

  /** Single sign-on is turned off. */
  NOT_ALLOWED(SsoDenialKind.LOGIN_REQUIRED, "Single sign-on is not allowed"),

  /** The requester asks for another set of attributes than the original authentication was made for. */
  OTHER_REQUESTED_ATTRIBUTES(SsoDenialKind.INTERACTION_REQUIRED,
      "The requester asks for another set of attributes than the original authentication");

  /** The kind of refusal. */
  private final SsoDenialKind kind;

  /** A description for logs and for the error that the requester is given. */
  private final String description;

  /**
   * Constructor.
   *
   * @param kind the kind of refusal
   * @param description a description for logs and for the error that the requester is given
   */
  SsoDenialReason(final SsoDenialKind kind, final String description) {
    this.kind = kind;
    this.description = description;
  }

  /**
   * Gets the kind of refusal.
   *
   * @return the kind of refusal
   */
  public @NonNull SsoDenialKind getKind() {
    return this.kind;
  }

  /**
   * Gets a description of the refusal, for logs and for the error that the requester is given.
   *
   * @return the description
   */
  public @NonNull String getDescription() {
    return this.description;
  }

}
