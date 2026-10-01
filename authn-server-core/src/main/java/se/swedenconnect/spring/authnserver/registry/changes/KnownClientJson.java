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
package se.swedenconnect.spring.authnserver.registry.changes;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.authentication.Requester;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.json.JsonMapper;

/**
 * Writes and reads {@link KnownClient} entries as JSON, for the stores that keep them outside the memory of the
 * server.
 *
 * @author Martin Lindström
 */
public final class KnownClientJson {

  /** The mapper. */
  private static final JsonMapper MAPPER = JsonMapper.builder()
      .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
      .build();

  /**
   * Writes one entry.
   *
   * @param client the entry
   * @return the JSON
   */
  public static @NonNull String write(final @NonNull KnownClient client) {
    return MAPPER.writeValueAsString(Entry.of(client));
  }

  /**
   * Writes a list of entries.
   *
   * @param clients the entries
   * @return the JSON
   */
  public static @NonNull String writeAll(final @NonNull Collection<KnownClient> clients) {
    return MAPPER.writeValueAsString(clients.stream().map(Entry::of).toList());
  }

  /**
   * Reads one entry.
   *
   * @param json the JSON
   * @return the entry
   * @throws IllegalArgumentException if the JSON is not a valid entry
   */
  public static @NonNull KnownClient read(final @NonNull String json) {
    try {
      return MAPPER.readValue(json, Entry.class).toKnownClient();
    }
    catch (final JacksonException | NullPointerException e) {
      throw new IllegalArgumentException("Invalid known client entry - " + e.getMessage(), e);
    }
  }

  /**
   * Reads a list of entries.
   *
   * @param json the JSON
   * @return the entries
   * @throws IllegalArgumentException if the JSON is not a valid list of entries
   */
  public static @NonNull List<KnownClient> readAll(final @NonNull String json) {
    try {
      final Entry[] entries = MAPPER.readValue(json, Entry[].class);
      final List<KnownClient> clients = new ArrayList<>();
      for (final Entry entry : entries) {
        clients.add(entry.toKnownClient());
      }
      return clients;
    }
    catch (final JacksonException | NullPointerException e) {
      throw new IllegalArgumentException("Invalid list of known clients - " + e.getMessage(), e);
    }
  }

  /**
   * An entry as it is written.
   *
   * @param protocol the protocol
   * @param identifier the identity of the client
   * @param organizationNumber the organisation number, or {@code null}
   * @param source the source
   */
  record Entry(@NonNull String protocol, @NonNull String identifier, @Nullable String organizationNumber,
      @NonNull String source) {

    /**
     * Creates the entry of a client.
     *
     * @param client the client
     * @return an {@link Entry}
     */
    static @NonNull Entry of(final @NonNull KnownClient client) {
      return new Entry(client.protocol().name(), client.identifier(), client.organizationNumber(), client.source());
    }

    /**
     * Creates the client of the entry.
     *
     * @return a {@link KnownClient}
     */
    @NonNull KnownClient toKnownClient() {
      return new KnownClient(new Requester(AuthenticationProtocol.valueOf(Objects.requireNonNull(this.protocol)),
          Objects.requireNonNull(this.identifier)), this.organizationNumber, Objects.requireNonNull(this.source));
    }

  }

  // Hidden constructor
  private KnownClientJson() {
  }

}
