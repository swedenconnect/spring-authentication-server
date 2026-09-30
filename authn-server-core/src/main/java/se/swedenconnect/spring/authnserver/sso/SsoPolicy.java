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

import java.io.Serial;
import java.io.Serializable;
import java.time.Duration;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import se.swedenconnect.spring.authnserver.LibraryVersion;

/**
 * When a previous authentication may be reused. The policy ranges from no single sign-on at all to single sign-on
 * for as long as the user's session lives.
 * <p>
 * The policy is set as a server default, and an authentication provider may override it. What the policy does not
 * decide, and what no configuration can turn off, are the rules that always apply: a new authentication is made when
 * the requester asks for one, when the previous authentication may not be reused, when the request carries a sign
 * message, and when a requested attribute value does not match the user.
 * </p>
 *
 * @author Martin Lindström
 */
public class SsoPolicy implements Serializable {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /** The default time limit, 60 minutes, which is the Sweden Connect maximum. */
  public static final Duration DEFAULT_TIME_LIMIT = Duration.ofMinutes(60);

  /** Whether single sign-on is allowed at all. */
  private boolean enabled = true;

  /** How old a previous authentication may be. */
  private Duration timeLimit = DEFAULT_TIME_LIMIT;

  /** Whether a previous authentication may only be reused for the requester it was made for. */
  private boolean sameRequesterRequired = true;

  /**
   * Default constructor, giving the default policy: single sign-on for {@link #DEFAULT_TIME_LIMIT}, for the same
   * requester only.
   */
  public SsoPolicy() {
  }

  /**
   * Creates the default policy: single sign-on for {@link #DEFAULT_TIME_LIMIT}, for the same requester only.
   *
   * @return an {@link SsoPolicy}
   */
  public static @NonNull SsoPolicy defaultPolicy() {
    return new SsoPolicy();
  }

  /**
   * Creates a policy that never allows single sign-on.
   *
   * @return an {@link SsoPolicy}
   */
  public static @NonNull SsoPolicy none() {
    final SsoPolicy policy = new SsoPolicy();
    policy.setEnabled(false);
    return policy;
  }

  /**
   * Creates a policy that allows single sign-on for as long as the user's session lives, for any requester.
   *
   * @return an {@link SsoPolicy}
   */
  public static @NonNull SsoPolicy forSessionLifetime() {
    final SsoPolicy policy = new SsoPolicy();
    policy.setTimeLimit(null);
    policy.setSameRequesterRequired(false);
    return policy;
  }

  /**
   * Predicate telling whether single sign-on is allowed at all. Defaults to {@code true}.
   *
   * @return {@code true} if single sign-on is allowed and {@code false} otherwise
   */
  public boolean isEnabled() {
    return this.enabled;
  }

  /**
   * Assigns whether single sign-on is allowed at all.
   *
   * @param enabled {@code true} if single sign-on is allowed and {@code false} otherwise
   */
  public void setEnabled(final boolean enabled) {
    this.enabled = enabled;
  }

  /**
   * Gets how old a previous authentication may be for it to be reused. Defaults to {@link #DEFAULT_TIME_LIMIT}.
   *
   * @return the time limit, or {@code null} if a previous authentication may be reused for as long as the session lives
   */
  public @Nullable Duration getTimeLimit() {
    return this.timeLimit;
  }

  /**
   * Assigns how old a previous authentication may be for it to be reused.
   *
   * @param timeLimit the time limit, or {@code null} to allow reuse for as long as the session lives
   */
  public void setTimeLimit(final @Nullable Duration timeLimit) {
    if (timeLimit != null && (timeLimit.isNegative() || timeLimit.isZero())) {
      throw new IllegalArgumentException("timeLimit must be positive");
    }
    this.timeLimit = timeLimit;
  }

  /**
   * Predicate telling whether a previous authentication may only be reused for the requester it was made for. "The same
   * requester" means the same protocol and the same requester identity. Defaults to {@code true}.
   *
   * @return {@code true} if only the same requester may reuse the authentication and {@code false} otherwise
   */
  public boolean isSameRequesterRequired() {
    return this.sameRequesterRequired;
  }

  /**
   * Assigns whether a previous authentication may only be reused for the requester it was made for.
   *
   * @param sameRequesterRequired {@code true} if only the same requester may reuse the authentication
   */
  public void setSameRequesterRequired(final boolean sameRequesterRequired) {
    this.sameRequesterRequired = sameRequesterRequired;
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return "enabled=%s, time-limit=%s, same-requester-required=%s".formatted(this.enabled,
        this.timeLimit != null ? this.timeLimit : "none", this.sameRequesterRequired);
  }

}
