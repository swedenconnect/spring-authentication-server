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
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

/**
 * An entry of the {@link FederationCache}: what the resolver answered about a client, or that it does not know the
 * client, and for how long the answer is kept.
 *
 * @param clientId the {@code client_id} of the client
 * @param metadata the client metadata, or {@code null} when the resolver does not know the client
 * @param trustMarkTypes the trust mark types of the resolve response
 * @param onDemandTrustMarks the trust marks that have been asked for on demand, keyed by type
 * @param expiresAt when the entry is no longer valid
 * @param invalidReason why the client is marked as invalid, or {@code null} if it is not, see
 *     {@link FederationClientValidator}
 * @param verifiedSector the successful check of the client's {@code sector_identifier_uri} that is remembered, or
 *     {@code null}
 * @param heldKeys the keys fetched from the client's {@code jwks_uri} or {@code signed_jwks_uri}, or {@code null}
 * @author Martin Lindström
 */
public record CachedClientRecord(
    @NonNull String clientId,
    @Nullable OIDCClientMetadata metadata,
    @NonNull Set<String> trustMarkTypes,
    @NonNull Map<String, OnDemandTrustMark> onDemandTrustMarks,
    @NonNull Instant expiresAt,
    @Nullable String invalidReason,
    @Nullable VerifiedSector verifiedSector,
    @Nullable HeldKeys heldKeys) {

  /**
   * Constructor.
   *
   * @param clientId the {@code client_id} of the client
   * @param metadata the client metadata, or {@code null}
   * @param trustMarkTypes the trust mark types of the resolve response
   * @param onDemandTrustMarks the trust marks that have been asked for on demand
   * @param expiresAt when the entry is no longer valid
   * @param invalidReason why the client is marked as invalid, or {@code null}
   * @param verifiedSector the successful check of the client's {@code sector_identifier_uri}, or {@code null}
   * @param heldKeys the keys fetched from the client's {@code jwks_uri} or {@code signed_jwks_uri}, or {@code null}
   */
  public CachedClientRecord {
    Objects.requireNonNull(clientId, "clientId must not be null");
    Objects.requireNonNull(expiresAt, "expiresAt must not be null");
    trustMarkTypes = Set.copyOf(Objects.requireNonNull(trustMarkTypes, "trustMarkTypes must not be null"));
    onDemandTrustMarks =
        Map.copyOf(Objects.requireNonNull(onDemandTrustMarks, "onDemandTrustMarks must not be null"));
  }

  /**
   * Constructor for an entry of a client that holds no keys.
   *
   * @param clientId the {@code client_id} of the client
   * @param metadata the client metadata, or {@code null}
   * @param trustMarkTypes the trust mark types of the resolve response
   * @param onDemandTrustMarks the trust marks that have been asked for on demand
   * @param expiresAt when the entry is no longer valid
   * @param invalidReason why the client is marked as invalid, or {@code null}
   * @param verifiedSector the successful check of the client's {@code sector_identifier_uri}, or {@code null}
   */
  public CachedClientRecord(final @NonNull String clientId, final @Nullable OIDCClientMetadata metadata,
      final @NonNull Set<String> trustMarkTypes, final @NonNull Map<String, OnDemandTrustMark> onDemandTrustMarks,
      final @NonNull Instant expiresAt, final @Nullable String invalidReason,
      final @Nullable VerifiedSector verifiedSector) {
    this(clientId, metadata, trustMarkTypes, onDemandTrustMarks, expiresAt, invalidReason, verifiedSector, null);
  }

  /**
   * Constructor for an entry of a client that is not marked as invalid, has no remembered check and holds no keys.
   *
   * @param clientId the {@code client_id} of the client
   * @param metadata the client metadata, or {@code null}
   * @param trustMarkTypes the trust mark types of the resolve response
   * @param onDemandTrustMarks the trust marks that have been asked for on demand
   * @param expiresAt when the entry is no longer valid
   */
  public CachedClientRecord(final @NonNull String clientId, final @Nullable OIDCClientMetadata metadata,
      final @NonNull Set<String> trustMarkTypes, final @NonNull Map<String, OnDemandTrustMark> onDemandTrustMarks,
      final @NonNull Instant expiresAt) {
    this(clientId, metadata, trustMarkTypes, onDemandTrustMarks, expiresAt, null, null, null);
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
  public static @NonNull CachedClientRecord found(final @NonNull ResolvedClient resolved, final @NonNull Instant now,
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
  public static @NonNull CachedClientRecord notFound(
      final @NonNull String clientId, final @NonNull Instant now, final @NonNull Duration timeToLive) {
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
   * Tells whether the client is valid, that is, not marked as invalid.
   *
   * @return {@code true} if the client is valid and {@code false} otherwise
   */
  public boolean isValid() {
    return this.invalidReason == null;
  }

  /**
   * Creates a copy of the entry with the outcome of the validation of the client. A temporary mark makes the entry
   * expire after the given time, unless it expires before that, so that the client is checked again when it is next
   * resolved.
   *
   * @param outcome the outcome of the validation
   * @param now the current time
   * @param temporaryMark how long a temporary mark lasts
   * @return a {@link CachedClientRecord}
   */
  public @NonNull CachedClientRecord withOutcome(final FederationClientValidator.@NonNull Outcome outcome,
      final @NonNull Instant now, final @NonNull Duration temporaryMark) {
    Objects.requireNonNull(outcome, "outcome must not be null");
    Instant expiry = this.expiresAt;
    if (outcome.temporary()) {
      final Instant until = now.plus(temporaryMark);
      if (until.isBefore(expiry)) {
        expiry = until;
      }
    }
    return new CachedClientRecord(this.clientId, this.metadata, this.trustMarkTypes, this.onDemandTrustMarks, expiry,
        outcome.invalidReason(), outcome.verifiedSector(), outcome.heldKeys());
  }

  /**
   * Creates a copy of the entry holding other keys, after the keys have been fetched again.
   *
   * @param heldKeys the keys
   * @return a {@link CachedClientRecord}
   */
  public @NonNull CachedClientRecord withHeldKeys(final @Nullable HeldKeys heldKeys) {
    return new CachedClientRecord(this.clientId, this.metadata, this.trustMarkTypes, this.onDemandTrustMarks,
        this.expiresAt, this.invalidReason, this.verifiedSector, heldKeys);
  }

  /**
   * Tells whether the entry is no longer valid.
   *
   * @param now the current time
   * @return {@code true} if the entry has expired and {@code false} otherwise
   */
  public boolean isExpired(final @NonNull Instant now) {
    return !now.isBefore(this.expiresAt);
  }

  /**
   * Gets the marks of the client: the trust mark types of the resolve response and the types of the trust marks that
   * have been asked for on demand and are still valid.
   *
   * @param now the current time
   * @return the marks of the client
   */
  public @NonNull Set<String> getMarks(final @NonNull Instant now) {
    if (this.onDemandTrustMarks.isEmpty()) {
      return this.trustMarkTypes;
    }
    final Set<String> marks = new LinkedHashSet<>(this.trustMarkTypes);
    this.onDemandTrustMarks.forEach((type, mark) -> {
      if (mark.isValid(now)) {
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
  public @NonNull CachedClientRecord withTrustMark(
      final @NonNull String type, final @Nullable Instant trustMarkExpiresAt) {
    return this.withTrustMark(new TrustMarkRequester.TrustMark(type, trustMarkExpiresAt));
  }

  /**
   * Creates a copy of the entry where a trust mark that was asked for on demand has been added. It is kept until the
   * earlier of the trust mark's expiry and the entry's own expiry.
   *
   * @param trustMark the trust mark
   * @return a {@link CachedClientRecord}
   */
  public @NonNull CachedClientRecord withTrustMark(final TrustMarkRequester.@NonNull TrustMark trustMark) {
    Objects.requireNonNull(trustMark, "trustMark must not be null");
    final Instant expiry = trustMark.expiresAt() == null || this.expiresAt.isBefore(trustMark.expiresAt())
        ? this.expiresAt
        : trustMark.expiresAt();
    return this.withTrustMark(
        new OnDemandTrustMark(trustMark.type(), trustMark.trustMark(), trustMark.expiresAt(), expiry));
  }

  /**
   * Creates a copy of the entry where a trust mark that was asked for on demand has been added or replaced.
   *
   * @param trustMark the trust mark
   * @return a {@link CachedClientRecord}
   */
  private @NonNull CachedClientRecord withTrustMark(final @NonNull OnDemandTrustMark trustMark) {
    final Map<String, OnDemandTrustMark> marks = new LinkedHashMap<>(this.onDemandTrustMarks);
    marks.put(trustMark.type(), trustMark);
    return new CachedClientRecord(this.clientId, this.metadata, this.trustMarkTypes, marks, this.expiresAt,
        this.invalidReason, this.verifiedSector, this.heldKeys);
  }

  /**
   * Creates a copy of the entry where a trust mark that was asked for on demand has been removed, for example because
   * its issuer has withdrawn it.
   *
   * @param type the trust mark type
   * @return a {@link CachedClientRecord}
   */
  public @NonNull CachedClientRecord withoutTrustMark(final @NonNull String type) {
    Objects.requireNonNull(type, "type must not be null");
    if (!this.onDemandTrustMarks.containsKey(type)) {
      return this;
    }
    final Map<String, OnDemandTrustMark> marks = new LinkedHashMap<>(this.onDemandTrustMarks);
    marks.remove(type);
    return new CachedClientRecord(this.clientId, this.metadata, this.trustMarkTypes, marks, this.expiresAt,
        this.invalidReason, this.verifiedSector, this.heldKeys);
  }

  /**
   * Creates a copy of the entry where the trust marks that were asked for on demand for an earlier entry have been
   * carried over. Marks that have expired, and marks that the resolve response now carries, are left out.
   *
   * @param earlier the earlier entry, or {@code null}
   * @param now the current time
   * @return a {@link CachedClientRecord}
   */
  public @NonNull CachedClientRecord carryOverTrustMarks(
      final @Nullable CachedClientRecord earlier, final @NonNull Instant now) {
    if (earlier == null || earlier.onDemandTrustMarks().isEmpty()) {
      return this;
    }
    CachedClientRecord result = this;
    for (final OnDemandTrustMark mark : earlier.onDemandTrustMarks().values()) {
      if (mark.isValid(now) && !this.trustMarkTypes.contains(mark.type())) {
        final Instant expiry = this.expiresAt.isBefore(mark.validUntil()) ? this.expiresAt : mark.validUntil();
        result = result.withTrustMark(
            new OnDemandTrustMark(mark.type(), mark.trustMark(), mark.trustMarkExpiresAt(), expiry));
      }
    }
    return result;
  }

}
