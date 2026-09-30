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
package se.swedenconnect.spring.authnserver.oidc.federation;

import java.time.Clock;
import java.time.Instant;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jwt.SignedJWT;

/**
 * Holds the signed entity configuration of the OpenID Provider and keeps it up to date, in the same way as the SAML
 * metadata is kept.
 * <p>
 * The entity configuration is checked each time it is asked for, and built and signed again only when needed: when
 * three quarters of its lifetime have passed, so that a fresh version is available well before it expires, and when
 * its content has changed, such as a renewed trust mark or a federation key that has changed state.
 * </p>
 *
 * @author Martin Lindström
 */
public class EntityConfigurationContainer {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(EntityConfigurationContainer.class);

  /** The part of the lifetime that passes before the entity configuration is signed again. */
  public static final double UPDATE_FACTOR = 0.75;

  /** Builds the entity configuration. */
  private final EntityConfigurationBuilder builder;

  /** The clock, so that tests can control time. */
  private final Clock clock;

  /** The current entity configuration, or {@code null} before it has been built. */
  private SignedJWT current;

  /** What the current entity configuration was built from. */
  private Object contentState;

  /** When the current entity configuration is built again. */
  private Instant updateAt;

  /**
   * Constructor.
   *
   * @param builder builds the entity configuration
   */
  public EntityConfigurationContainer(final @NonNull EntityConfigurationBuilder builder) {
    this(builder, Clock.systemUTC());
  }

  /**
   * Constructor.
   *
   * @param builder builds the entity configuration
   * @param clock the clock to use
   */
  public EntityConfigurationContainer(final @NonNull EntityConfigurationBuilder builder, final @NonNull Clock clock) {
    this.builder = Objects.requireNonNull(builder, "builder must not be null");
    this.clock = Objects.requireNonNull(clock, "clock must not be null");
  }

  /**
   * Gets the entity configuration, building and signing it again if it is out of date.
   *
   * @return the signed entity configuration
   * @throws IllegalStateException if the entity configuration cannot be built or signed
   */
  public synchronized @NonNull SignedJWT getEntityConfiguration() {
    final Instant now = this.clock.instant();
    final Object state = this.builder.getContentState();
    if (this.current == null || !now.isBefore(this.updateAt) || !state.equals(this.contentState)) {
      log.debug("Building the entity configuration ({})", this.current == null ? "first time"
          : !state.equals(this.contentState) ? "content changed" : "about to expire");
      this.current = this.builder.build(now);
      this.contentState = state;
      this.updateAt = now.plusMillis((long) (this.builder.getLifetime().toMillis() * UPDATE_FACTOR));
    }
    return this.current;
  }

}
