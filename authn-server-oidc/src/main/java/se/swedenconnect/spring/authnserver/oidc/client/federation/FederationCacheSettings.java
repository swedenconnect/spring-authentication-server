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
package se.swedenconnect.spring.authnserver.oidc.client.federation;

import java.time.Duration;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * How resolved clients are cached.
 *
 * @param maximumAge how long an entry may live at the most, regardless of what the resolve response says, or
 *          {@code null} for no limit. No limit is the default
 * @param notFoundTimeToLive how long the answer that the resolver does not know a client is kept, so that repeated
 *          requests for the same unknown {@code client_id} do not each reach the resolver. A resolver that fails is
 *          never cached. It is also how long a client is marked as invalid when its keys, or the document at its
 *          {@code sector_identifier_uri}, cannot be fetched
 * @param trustMarkNotFoundTimeToLive how long the answer from a trust mark issuer that it has not issued a trust mark
 *          to a client is kept, so that the issuer is not asked again for each request. The answer is never kept
 *          longer than the client's cache entry
 * @author Martin Lindström
 */
public record FederationCacheSettings(
    @Nullable Duration maximumAge,
    @NonNull Duration notFoundTimeToLive,
    @NonNull Duration trustMarkNotFoundTimeToLive) {

  /** The default time that the answer that a client is unknown is kept: five minutes. */
  public static final Duration DEFAULT_NOT_FOUND_TIME_TO_LIVE = Duration.ofMinutes(5);

  /** The default time that the answer that a trust mark issuer has no trust mark for a client is kept: one hour. */
  public static final Duration DEFAULT_TRUST_MARK_NOT_FOUND_TIME_TO_LIVE = Duration.ofHours(1);

  /**
   * Constructor.
   *
   * @param maximumAge how long an entry may live at the most, or {@code null}
   * @param notFoundTimeToLive how long the answer that the resolver does not know a client is kept
   * @param trustMarkNotFoundTimeToLive how long the answer that a trust mark issuer has no trust mark for a client is
   *     kept
   */
  public FederationCacheSettings {
    Objects.requireNonNull(notFoundTimeToLive, "notFoundTimeToLive must not be null");
    Objects.requireNonNull(trustMarkNotFoundTimeToLive, "trustMarkNotFoundTimeToLive must not be null");
    if (maximumAge != null && (maximumAge.isZero() || maximumAge.isNegative())) {
      throw new IllegalArgumentException("maximumAge must be a positive duration");
    }
    if (notFoundTimeToLive.isZero() || notFoundTimeToLive.isNegative()) {
      throw new IllegalArgumentException("notFoundTimeToLive must be a positive duration");
    }
    if (trustMarkNotFoundTimeToLive.isZero() || trustMarkNotFoundTimeToLive.isNegative()) {
      throw new IllegalArgumentException("trustMarkNotFoundTimeToLive must be a positive duration");
    }
  }

  /**
   * Constructor with the default time that the answer that a trust mark issuer has no trust mark for a client is
   * kept.
   *
   * @param maximumAge how long an entry may live at the most, or {@code null}
   * @param notFoundTimeToLive how long the answer that the resolver does not know a client is kept
   */
  public FederationCacheSettings(final @Nullable Duration maximumAge, final @NonNull Duration notFoundTimeToLive) {
    this(maximumAge, notFoundTimeToLive, DEFAULT_TRUST_MARK_NOT_FOUND_TIME_TO_LIVE);
  }

  /**
   * Creates the default settings: no maximum age.
   *
   * @return a {@link FederationCacheSettings}
   */
  public static @NonNull FederationCacheSettings defaults() {
    return new FederationCacheSettings(null, DEFAULT_NOT_FOUND_TIME_TO_LIVE, DEFAULT_TRUST_MARK_NOT_FOUND_TIME_TO_LIVE);
  }

}
