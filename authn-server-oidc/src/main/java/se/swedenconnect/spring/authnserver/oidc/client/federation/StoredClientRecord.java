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

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import com.nimbusds.oauth2.sdk.ParseException;
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
 * @author Martin Lindström
 */
record StoredClientRecord(@NonNull String clientId, @Nullable String metadata, @Nullable Set<String> trustMarkTypes,
    @Nullable List<OnDemandTrustMark> onDemandTrustMarks, @NonNull Instant expiresAt) {

  /**
   * Creates the stored form of a cache record.
   *
   * @param record the record
   * @return a {@link StoredClientRecord}
   */
  static @NonNull StoredClientRecord of(final @NonNull CachedClientRecord record) {
    return new StoredClientRecord(record.clientId(),
        record.metadata() != null ? record.metadata().toJSONObject().toJSONString() : null,
        record.trustMarkTypes(), List.copyOf(record.onDemandTrustMarks().values()), record.expiresAt());
  }

  /**
   * Creates the cache record of the stored form.
   *
   * @return a {@link CachedClientRecord}
   * @throws ParseException if the client metadata cannot be parsed
   */
  @NonNull CachedClientRecord toRecord() throws ParseException {
    final Map<String, OnDemandTrustMark> marks = this.onDemandTrustMarks == null
        ? Map.of()
        : this.onDemandTrustMarks.stream().collect(Collectors.toMap(OnDemandTrustMark::type, Function.identity()));
    return new CachedClientRecord(this.clientId,
        this.metadata != null ? OIDCClientMetadata.parse(JSONObjectUtils.parse(this.metadata)) : null,
        this.trustMarkTypes != null ? this.trustMarkTypes : Set.of(), marks, this.expiresAt);
  }

}
