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

import java.text.ParseException;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

/**
 * A {@link CachedClientRecord} as it is written outside the memory of the server, to Redis or to a file. The client
 * metadata is kept as the JSON that the metadata gives.
 *
 * @param clientId the {@code client_id}
 * @param metadata the client metadata as a JSON object, or {@code null}
 * @param trustMarkTypes the trust mark types of the resolve response
 * @param onDemandTrustMarks the trust marks that have been asked for on demand
 * @param expiresAt when the entry is no longer valid
 * @param invalidReason why the client is marked as invalid, or {@code null}
 * @param verifiedSector the successful check of the client's {@code sector_identifier_uri}, or {@code null}
 * @param keysUri the URI that the held keys were fetched from, or {@code null} if no keys are held
 * @param keysSigned whether the held keys come from a {@code signed_jwks_uri}, or {@code null}
 * @param keys the held keys as a JWK Set, or {@code null}
 * @param entityKeys the Federation Entity Keys that verify a signed JWK Set, as a JWK Set, or {@code null}
 * @author Martin Lindström
 */
record StoredClientRecord(@NonNull String clientId, @Nullable String metadata, @Nullable Set<String> trustMarkTypes,
    @Nullable List<OnDemandTrustMark> onDemandTrustMarks, @NonNull Instant expiresAt, @Nullable String invalidReason,
    @Nullable VerifiedSector verifiedSector, @Nullable String keysUri, @Nullable Boolean keysSigned,
    @Nullable String keys, @Nullable String entityKeys) {

  /**
   * Creates the stored form of a cache record.
   *
   * @param record the record
   * @return a {@link StoredClientRecord}
   */
  static @NonNull StoredClientRecord of(final @NonNull CachedClientRecord record) {
    final HeldKeys held = record.heldKeys();
    return new StoredClientRecord(record.clientId(),
        record.metadata() != null ? record.metadata().toJSONObject().toJSONString() : null,
        record.trustMarkTypes(), List.copyOf(record.onDemandTrustMarks().values()), record.expiresAt(),
        record.invalidReason(), record.verifiedSector(), held != null ? held.uri() : null,
        held != null ? held.signed() : null, held != null ? write(held.keys()) : null,
        held != null ? write(held.entityKeys()) : null);
  }

  /**
   * Creates the cache record of the stored form.
   *
   * @return a {@link CachedClientRecord}
   * @throws com.nimbusds.oauth2.sdk.ParseException if the client metadata cannot be parsed
   * @throws IllegalArgumentException if the held keys cannot be parsed
   */
  @NonNull CachedClientRecord toRecord() throws com.nimbusds.oauth2.sdk.ParseException {
    final Map<String, OnDemandTrustMark> marks = this.onDemandTrustMarks == null
        ? Map.of()
        : this.onDemandTrustMarks.stream().collect(Collectors.toMap(OnDemandTrustMark::type, Function.identity()));
    return new CachedClientRecord(this.clientId,
        this.metadata != null ? OIDCClientMetadata.parse(JSONObjectUtils.parse(this.metadata)) : null,
        this.trustMarkTypes != null ? this.trustMarkTypes : Set.of(), marks, this.expiresAt, this.invalidReason,
        this.verifiedSector, this.keysUri != null && this.keys != null
            ? new HeldKeys(this.keysUri, Boolean.TRUE.equals(this.keysSigned), readKeys(this.keys),
                readKeys(this.entityKeys))
            : null);
  }

  /**
   * Writes a JWK Set as JSON, with public keys only.
   *
   * @param keys the JWK Set, or {@code null}
   * @return the JSON, or {@code null}
   */
  static @Nullable String write(final @Nullable JWKSet keys) {
    return keys != null ? keys.toString(true) : null;
  }

  /**
   * Reads a JWK Set written by {@link #write(JWKSet)}.
   *
   * @param json the JSON, or {@code null}
   * @return the JWK Set, or {@code null}
   * @throws IllegalArgumentException if the JSON is not a JWK Set
   */
  static @Nullable JWKSet readKeys(final @Nullable String json) {
    if (json == null) {
      return null;
    }
    try {
      return JWKSet.parse(json);
    }
    catch (final ParseException e) {
      throw new IllegalArgumentException("Invalid JWK Set - " + e.getMessage(), e);
    }
  }

}
