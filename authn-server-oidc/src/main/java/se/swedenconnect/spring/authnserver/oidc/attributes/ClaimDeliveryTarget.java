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
package se.swedenconnect.spring.authnserver.oidc.attributes;

import java.io.Serializable;
import java.util.Objects;

import org.jspecify.annotations.NonNull;

import se.swedenconnect.spring.authnserver.attributes.MergeableProtocolData;

/**
 * Where a requested claim is to be delivered.
 * <p>
 * This is carried as protocol data on a
 * {@link se.swedenconnect.spring.authnserver.attributes.GenericRequestedAttribute} under the key
 * {@link #PROTOCOL_DATA_KEY}. The generic layer never looks at it.
 * </p>
 * <p>
 * A claim may be asked for by more than one source, for example by a scope and by the claims request parameter. The
 * targets are then combined, so a claim that one source wants in the ID token and another wants from the UserInfo
 * endpoint is delivered in both places. This is what Section 4.2 of the Swedish OpenID Connect Profile calls for.
 * </p>
 *
 * @author Martin Lindström
 */
public enum ClaimDeliveryTarget implements MergeableProtocolData {

  /** The claim is to be delivered in the ID token. */
  ID_TOKEN,

  /** The claim is to be delivered from the UserInfo endpoint. */
  USER_INFO,

  /** The claim is to be delivered both in the ID token and from the UserInfo endpoint. */
  ID_TOKEN_AND_USER_INFO;

  /** The key under which the delivery target is stored as protocol data. */
  public static final String PROTOCOL_DATA_KEY = "oidc.delivery-target";

  /**
   * Gets the target matching the supplied flags. At least one of them must be set.
   *
   * @param idToken whether the claim is to be delivered in the ID token
   * @param userInfo whether the claim is to be delivered from the UserInfo endpoint
   * @return a {@link ClaimDeliveryTarget}
   */
  public static @NonNull ClaimDeliveryTarget of(final boolean idToken, final boolean userInfo) {
    if (idToken && userInfo) {
      return ID_TOKEN_AND_USER_INFO;
    }
    if (idToken) {
      return ID_TOKEN;
    }
    if (userInfo) {
      return USER_INFO;
    }
    throw new IllegalArgumentException("At least one delivery target must be given");
  }

  /**
   * Predicate telling whether the claim is to be delivered in the ID token.
   *
   * @return {@code true} if the claim is to be delivered in the ID token and {@code false} otherwise
   */
  public boolean isIdToken() {
    return this != USER_INFO;
  }

  /**
   * Predicate telling whether the claim is to be delivered from the UserInfo endpoint.
   *
   * @return {@code true} if the claim is to be delivered from the UserInfo endpoint and {@code false} otherwise
   */
  public boolean isUserInfo() {
    return this != ID_TOKEN;
  }

  /**
   * Combines this target with another, giving the target that covers both.
   *
   * @param other the target to combine with
   * @return a {@link ClaimDeliveryTarget}
   */
  public @NonNull ClaimDeliveryTarget combine(final @NonNull ClaimDeliveryTarget other) {
    Objects.requireNonNull(other, "other must not be null");
    return of(this.isIdToken() || other.isIdToken(), this.isUserInfo() || other.isUserInfo());
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull Serializable mergeWith(final @NonNull Serializable other) {
    return other instanceof final ClaimDeliveryTarget target ? this.combine(target) : this;
  }

}
