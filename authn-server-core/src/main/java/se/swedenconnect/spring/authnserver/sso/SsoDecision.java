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
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import se.swedenconnect.spring.authnserver.LibraryVersion;

/**
 * A decision about reusing a previous authentication. It is what an {@link SsoVoter} returns, and also the outcome of
 * the whole vote.
 *
 * @param vote the vote
 * @param reason why single sign-on was refused, set only when the vote is {@link Vote#DENY}
 * @author Martin Lindström
 */
public record SsoDecision(@NonNull Vote vote, @Nullable SsoDenialReason reason) implements Serializable {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /** How a voter, or the whole vote, came out. */
  public enum Vote {

    /** The previous authentication may be reused. */
    ALLOW,

    /** The previous authentication must not be reused. */
    DENY,

    /** No opinion. */
    ABSTAIN

  }

  /**
   * Constructor.
   *
   * @param vote the vote
   * @param reason why single sign-on was refused, required for {@link Vote#DENY} and not allowed otherwise
   */
  public SsoDecision {
    Objects.requireNonNull(vote, "vote must not be null");
    if (vote == Vote.DENY && reason == null) {
      throw new IllegalArgumentException("A denial must state its reason");
    }
    if (vote != Vote.DENY && reason != null) {
      throw new IllegalArgumentException("Only a denial may state a reason");
    }
  }

  /**
   * The previous authentication may be reused.
   *
   * @return an {@link SsoDecision}
   */
  public static @NonNull SsoDecision allow() {
    return new SsoDecision(Vote.ALLOW, null);
  }

  /**
   * No opinion. Single sign-on needs at least one {@link #allow()} and no denial, so a decision where every voter
   * abstains means no single sign-on.
   *
   * @return an {@link SsoDecision}
   */
  public static @NonNull SsoDecision abstain() {
    return new SsoDecision(Vote.ABSTAIN, null);
  }

  /**
   * The previous authentication must not be reused.
   *
   * @param reason why it must not be reused
   * @return an {@link SsoDecision}
   */
  public static @NonNull SsoDecision deny(final @NonNull SsoDenialReason reason) {
    return new SsoDecision(Vote.DENY, Objects.requireNonNull(reason, "reason must not be null"));
  }

  /**
   * Predicate telling whether the previous authentication may be reused.
   *
   * @return {@code true} if it may be reused and {@code false} otherwise
   */
  public boolean isAllowed() {
    return this.vote == Vote.ALLOW;
  }

  /**
   * Predicate telling whether the previous authentication must not be reused.
   *
   * @return {@code true} if it must not be reused and {@code false} otherwise
   */
  public boolean isDenied() {
    return this.vote == Vote.DENY;
  }

}
