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

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;

import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

/**
 * An entry of the {@link FederationCache}: what the resolver answered about a client, or that it does not know the
 * client, and for how long the answer is kept.
 *
 * @param clientId the {@code client_id} of the client
 * @param metadata the client metadata, or {@code null} when the resolver does not know the client
 * @param trustMarkTypes the trust mark types of the resolve response
 * @param onDemandTrustMarks the trust marks that have been asked for on demand, as the type and when it is no longer
 *          valid
 * @param expiresAt when the entry is no longer valid
 * @author Martin Lindström
 */
public record CachedClientRecord(
    @Nonnull String clientId,
    @Nullable OIDCClientMetadata metadata,
    @Nonnull Set<String> trustMarkTypes,
    @Nonnull Map<String, Instant> onDemandTrustMarks,
    @Nonnull Instant expiresAt) {

  /**
   * Constructor.
   *
   * @param clientId the {@code client_id} of the client
   * @param metadata the client metadata, or {@code null}
   * @param trustMarkTypes the trust mark types of the resolve response
   * @param onDemandTrustMarks the trust marks that have been asked for on demand
   * @param expiresAt when the entry is no longer valid
   */
  public CachedClientRecord {
    Objects.requireNonNull(clientId, "clientId must not be null");
    Objects.requireNonNull(expiresAt, "expiresAt must not be null");
    trustMarkTypes = Set.copyOf(Objects.requireNonNull(trustMarkTypes, "trustMarkTypes must not be null"));
    onDemandTrustMarks =
        Map.copyOf(Objects.requireNonNull(onDemandTrustMarks, "onDemandTrustMarks must not be null"));
  }

  /**
   * Creates an entry for a client that the resolver knows. The entry lives until the resolve response expires, or
   * until the maximum age has passed if that comes first.
   *
   * @param resolved what the resolver answered
   * @param now the current time
   * @param maximumAge how long an entry may live at the most, or {@code null} for no limit
   * @return a {@link CachedClientRecord}
   */
  public static @Nonnull CachedClientRecord found(final @Nonnull ResolvedClient resolved, final @Nonnull Instant now,
      final @Nullable Duration maximumAge) {
    Objects.requireNonNull(resolved, "resolved must not be null");
    Instant expiresAt = resolved.expiresAt();
    if (maximumAge != null) {
      final Instant maximum = now.plus(maximumAge);
      if (maximum.isBefore(expiresAt)) {
        expiresAt = maximum;
      }
    }
    return new CachedClientRecord(
        resolved.clientId(), resolved.metadata(), resolved.trustMarkTypes(), Map.of(), expiresAt);
  }

  /**
   * Creates an entry telling that the resolver does not know the client. Such an entry is kept for a short time so
   * that repeated requests for the same unknown client do not each reach the resolver.
   *
   * @param clientId the {@code client_id} of the client
   * @param now the current time
   * @param timeToLive how long the entry is kept
   * @return a {@link CachedClientRecord}
   */
  public static @Nonnull CachedClientRecord notFound(
      final @Nonnull String clientId, final @Nonnull Instant now, final @Nonnull Duration timeToLive) {
    return new CachedClientRecord(clientId, null, Set.of(), Map.of(), now.plus(timeToLive));
  }

  /**
   * Tells whether the entry holds a client. An entry that does not is the resolver's answer that it does not know
   * the client.
   *
   * @return {@code true} if the entry holds a client and {@code false} otherwise
   */
  public boolean isFound() {
    return this.metadata != null;
  }

  /**
   * Tells whether the entry is no longer valid.
   *
   * @param now the current time
   * @return {@code true} if the entry has expired and {@code false} otherwise
   */
  public boolean isExpired(final @Nonnull Instant now) {
    return !now.isBefore(this.expiresAt);
  }

  /**
   * Gets the marks of the client: the trust mark types of the resolve response and the types of the trust marks that
   * have been asked for on demand and are still valid.
   *
   * @param now the current time
   * @return the marks of the client
   */
  public @Nonnull Set<String> getMarks(final @Nonnull Instant now) {
    if (this.onDemandTrustMarks.isEmpty()) {
      return this.trustMarkTypes;
    }
    final Set<String> marks = new LinkedHashSet<>(this.trustMarkTypes);
    this.onDemandTrustMarks.forEach((type, expiresAt) -> {
      if (now.isBefore(expiresAt)) {
        marks.add(type);
      }
    });
    return Set.copyOf(marks);
  }

  /**
   * Creates a copy of the entry where a trust mark that was asked for on demand has been added. It is kept until the
   * earlier of the trust mark's expiry and the entry's own expiry.
   *
   * @param type the trust mark type
   * @param trustMarkExpiresAt when the trust mark is no longer valid, or {@code null} if it does not expire
   * @return a {@link CachedClientRecord}
   */
  public @Nonnull CachedClientRecord withTrustMark(
      final @Nonnull String type, final @Nullable Instant trustMarkExpiresAt) {
    Objects.requireNonNull(type, "type must not be null");
    final Instant expiry = trustMarkExpiresAt == null || this.expiresAt.isBefore(trustMarkExpiresAt)
        ? this.expiresAt
        : trustMarkExpiresAt;
    final Map<String, Instant> marks = new LinkedHashMap<>(this.onDemandTrustMarks);
    marks.put(type, expiry);
    return new CachedClientRecord(this.clientId, this.metadata, this.trustMarkTypes, marks, this.expiresAt);
  }

  /**
   * Creates a copy of the entry where the trust marks that were asked for on demand for an earlier entry have been
   * carried over. Marks that have expired, and marks that the resolve response now carries, are left out.
   *
   * @param earlier the earlier entry, or {@code null}
   * @param now the current time
   * @return a {@link CachedClientRecord}
   */
  public @Nonnull CachedClientRecord carryOverTrustMarks(
      final @Nullable CachedClientRecord earlier, final @Nonnull Instant now) {
    if (earlier == null || earlier.onDemandTrustMarks().isEmpty()) {
      return this;
    }
    CachedClientRecord result = this;
    for (final Map.Entry<String, Instant> mark : earlier.onDemandTrustMarks().entrySet()) {
      if (now.isBefore(mark.getValue()) && !this.trustMarkTypes.contains(mark.getKey())) {
        result = result.withTrustMark(mark.getKey(), mark.getValue());
      }
    }
    return result;
  }

}
