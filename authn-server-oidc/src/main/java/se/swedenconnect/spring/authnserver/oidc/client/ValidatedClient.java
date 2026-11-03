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
package se.swedenconnect.spring.authnserver.oidc.client;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import com.nimbusds.jose.util.JSONObjectUtils;

/**
 * The outcome of the validation of a client from the configuration or a client repository, see
 * {@link ClientValidation}, kept in a {@link ClientValidationStore}.
 *
 * @param clientId the {@code client_id} of the client
 * @param fingerprint the fingerprint of the metadata that was validated, see {@link #fingerprint(OidcClientRecord)}
 * @param invalidReason why the client is invalid, or {@code null} if it is valid
 * @param invalidUntil when a temporary mark runs out, or {@code null} if the client is valid or the mark lasts until
 *     the metadata changes
 * @param heldKeys the keys read from the client's {@code jwks_uri}, or {@code null}
 * @author Martin Lindström
 */
public record ValidatedClient(@NonNull String clientId, @NonNull String fingerprint, @Nullable String invalidReason,
    @Nullable Instant invalidUntil, @Nullable HeldKeys heldKeys) {

  /**
   * Constructor.
   *
   * @param clientId the {@code client_id} of the client
   * @param fingerprint the fingerprint of the metadata that was validated
   * @param invalidReason why the client is invalid, or {@code null} if it is valid
   * @param invalidUntil when a temporary mark runs out, or {@code null}
   * @param heldKeys the keys read from the client's {@code jwks_uri}, or {@code null}
   */
  public ValidatedClient {
    Objects.requireNonNull(clientId, "clientId must not be null");
    Objects.requireNonNull(fingerprint, "fingerprint must not be null");
  }

  /**
   * Tells whether the client is valid.
   *
   * @return {@code true} if the client is valid and {@code false} otherwise
   */
  public boolean isValid() {
    return this.invalidReason == null;
  }

  /**
   * Tells whether a temporary mark has run out, so that the client is to be validated again.
   *
   * @param now the current time
   * @return {@code true} if the client has a temporary mark that has run out and {@code false} otherwise
   */
  public boolean isMarkExpired(final @NonNull Instant now) {
    return this.invalidUntil != null && !now.isBefore(this.invalidUntil);
  }

  /**
   * Creates a copy holding other keys, after the keys have been read again.
   *
   * @param heldKeys the keys
   * @return a {@link ValidatedClient}
   */
  public @NonNull ValidatedClient withHeldKeys(final @Nullable HeldKeys heldKeys) {
    return new ValidatedClient(this.clientId, this.fingerprint, this.invalidReason, this.invalidUntil, heldKeys);
  }

  /**
   * Computes the fingerprint of what is validated for a client: its metadata, and whether it has a client secret. The
   * value of the secret is not part of it. A changed fingerprint tells that the client is to be validated again.
   *
   * @param client the client
   * @return the fingerprint
   */
  public static @NonNull String fingerprint(final @NonNull OidcClientRecord client) {
    final Map<String, Object> metadata = new HashMap<>(client.metadata().toJSONObject());
    metadata.remove(OidcClientRecord.CLIENT_SECRET);
    final String json = JSONObjectUtils.toJSONString(sorted(metadata));
    final boolean hasSecret = OidcClientRecord.getClientSecret(client.metadata()) != null;
    try {
      final byte[] digest = MessageDigest.getInstance("SHA-256")
          .digest((json + (hasSecret ? "|secret" : "")).getBytes(StandardCharsets.UTF_8));
      return HexFormat.of().formatHex(digest);
    }
    catch (final NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 is not supported", e);
    }
  }

  /**
   * Gives a JSON object with its members, and those of nested objects, in a fixed order.
   *
   * @param object the JSON object
   * @return a sorted copy
   */
  private static @NonNull Map<String, Object> sorted(final @NonNull Map<String, Object> object) {
    final Map<String, Object> sorted = new TreeMap<>();
    object.forEach((name, value) -> sorted.put(name, sortedValue(value)));
    return sorted;
  }

  /**
   * Gives a JSON value with the members of any object in a fixed order.
   *
   * @param value the value
   * @return the value, sorted
   */
  @SuppressWarnings("unchecked")
  private static @Nullable Object sortedValue(final @Nullable Object value) {
    if (value instanceof final Map<?, ?> map) {
      return sorted((Map<String, Object>) map);
    }
    if (value instanceof final List<?> list) {
      return list.stream().map(ValidatedClient::sortedValue).toList();
    }
    return value;
  }

}
