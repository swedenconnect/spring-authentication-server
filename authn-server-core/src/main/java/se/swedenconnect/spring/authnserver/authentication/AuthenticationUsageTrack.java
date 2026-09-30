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
package se.swedenconnect.spring.authnserver.authentication;

import java.io.Serial;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import se.swedenconnect.spring.authnserver.LibraryVersion;

/**
 * Remembers every time an authentication result has been used. The first record is the original authentication, and
 * every record after that is a use where single sign-on was applied.
 * <p>
 * The records are what the single sign-on policies work on. A policy may need to know when the result was created, by
 * which requester, under which protocol, and which attributes that requester asked for.
 * </p>
 *
 * @author Martin Lindström
 */
public class AuthenticationUsageTrack implements Serializable {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /** All the times the authentication result has been used, oldest first. */
  private final List<AuthenticationUse> usages = new ArrayList<>();

  /**
   * Constructor setting up an empty track.
   */
  public AuthenticationUsageTrack() {
  }

  /**
   * Constructor setting up a track holding the original authentication.
   *
   * @param originalAuthentication the original authentication
   */
  public AuthenticationUsageTrack(final @NonNull AuthenticationUse originalAuthentication) {
    this.registerUse(originalAuthentication);
  }

  /**
   * Registers a use of the authentication result.
   *
   * @param use the use to register
   */
  public void registerUse(final @NonNull AuthenticationUse use) {
    this.usages.add(Objects.requireNonNull(use, "use must not be null"));
  }

  /**
   * Gets the record of the original authentication, which is the first record of the track.
   *
   * @return the original authentication, or {@code null} if no use has been registered
   */
  public @Nullable AuthenticationUse getOriginalAuthentication() {
    return this.usages.isEmpty() ? null : this.usages.getFirst();
  }

  /**
   * Gets the record of the latest use of the authentication result.
   *
   * @return the latest use, or {@code null} if no use has been registered
   */
  public @Nullable AuthenticationUse getLatestUse() {
    return this.usages.isEmpty() ? null : this.usages.getLast();
  }

  /**
   * Gets all the times the authentication result has been used, oldest first.
   *
   * @return a list of usage records, possibly empty
   */
  public @NonNull List<AuthenticationUse> getUsages() {
    return Collections.unmodifiableList(this.usages);
  }

  /**
   * Gets the number of registered uses of the authentication result.
   *
   * @return the number of registered uses
   */
  public int size() {
    return this.usages.size();
  }

  /** {@inheritDoc} */
  @Override
  public boolean equals(final Object obj) {
    if (this == obj) {
      return true;
    }
    if (!(obj instanceof final AuthenticationUsageTrack other)) {
      return false;
    }
    return Objects.equals(this.usages, other.usages);
  }

  /** {@inheritDoc} */
  @Override
  public int hashCode() {
    return Objects.hash(this.usages);
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return this.usages.toString();
  }

}
