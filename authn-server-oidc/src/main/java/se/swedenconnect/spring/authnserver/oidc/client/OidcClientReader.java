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

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.core.io.Resource;
import org.springframework.util.StreamUtils;
import org.springframework.util.StringUtils;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;

/**
 * Reads statically configured OpenID Connect clients into {@link OidcClientRecord}s, for a
 * {@link ConfigurationClientBackend}.
 * <p>
 * A client is given either directly, see {@link #addClient(String, String, String, Collection, String)}, or in a JSON
 * resource holding one client object or an array of client objects, see {@link #readLocation(Resource)}. A client
 * object has the following fields:
 * </p>
 * <ul>
 * <li>{@code client_id} - the client identifier, required.</li>
 * <li>{@code client_secret} - the client secret, for a client that authenticates with one.</li>
 * <li>{@code trust_mark_types} - an array of trust mark types that the operator assigns to the client.</li>
 * <li>{@code metadata} - the client metadata, as a JSON object, required.</li>
 * </ul>
 * <p>
 * The client metadata never holds a client secret, and a {@code client_id} in it must equal the client identifier.
 * A client identifier may only be given once over everything that is read by one reader.
 * </p>
 *
 * @author Martin Lindström
 */
public class OidcClientReader {

  /** The field of a client object holding the client identifier. */
  public static final String CLIENT_ID = "client_id";

  /** The field of a client object holding the client secret. */
  public static final String CLIENT_SECRET = OidcClientRecord.CLIENT_SECRET;

  /** The field of a client object holding the trust mark types that the operator assigns. */
  public static final String TRUST_MARK_TYPES = "trust_mark_types";

  /** The field of a client object holding the client metadata. */
  public static final String METADATA = "metadata";

  /** The fields that a client object may have. */
  private static final Set<String> FIELDS = Set.of(CLIENT_ID, CLIENT_SECRET, TRUST_MARK_TYPES, METADATA);

  /** The clients read, in the order they were given. */
  private final List<OidcClientRecord> clients = new ArrayList<>();

  /** Where each client was given, keyed by client identifier. */
  private final Map<String, String> origins = new HashMap<>();

  /**
   * Reads the clients of a JSON resource, holding one client object or an array of client objects.
   *
   * @param location the resource
   * @return this reader
   * @throws IllegalArgumentException if the resource cannot be read, does not hold client objects, holds an invalid
   *     client, or holds a client that has already been given
   */
  public @NonNull OidcClientReader readLocation(final @NonNull Resource location) {
    Objects.requireNonNull(location, "location must not be null");
    final String origin = location.getDescription();
    final Object json;
    try (final InputStream is = location.getInputStream()) {
      json = new JSONParser(JSONParser.MODE_RFC4627).parse(StreamUtils.copyToString(is, StandardCharsets.UTF_8));
    }
    catch (final IOException | net.minidev.json.parser.ParseException e) {
      throw new IllegalArgumentException("Failed to read OpenID Connect clients from %s - %s"
          .formatted(origin, e.getMessage()), e);
    }
    if (json instanceof final JSONObject object) {
      this.add(toClient(object, origin), origin);
    }
    else if (json instanceof final JSONArray array) {
      for (final Object element : array) {
        if (!(element instanceof final JSONObject object)) {
          throw new IllegalArgumentException(
              "%s holds an array element that is not a JSON object".formatted(origin));
        }
        this.add(toClient(object, origin), origin);
      }
    }
    else {
      throw new IllegalArgumentException(
          "%s does not hold a JSON object or an array of JSON objects".formatted(origin));
    }
    return this;
  }

  /**
   * Adds a client that is given directly.
   *
   * @param clientId the client identifier
   * @param metadata the client metadata, as a JSON object
   * @param clientSecret the client secret, or {@code null} for a client that does not authenticate with one
   * @param trustMarkTypes the trust mark types that the operator assigns to the client, or {@code null} for none
   * @param origin where the client was given, for error messages
   * @return this reader
   * @throws IllegalArgumentException if the client is invalid or has already been given
   */
  public @NonNull OidcClientReader addClient(final @Nullable String clientId, final @Nullable String metadata,
      final @Nullable String clientSecret, final @Nullable Collection<String> trustMarkTypes,
      final @NonNull String origin) {
    Objects.requireNonNull(origin, "origin must not be null");
    if (!StringUtils.hasText(clientId)) {
      throw new IllegalArgumentException("A client of %s has no client identifier".formatted(origin));
    }
    if (!StringUtils.hasText(metadata)) {
      throw new IllegalArgumentException(
          "The OpenID Connect client '%s' of %s has no metadata".formatted(clientId, origin));
    }
    final Object json;
    try {
      json = new JSONParser(JSONParser.MODE_RFC4627).parse(metadata);
    }
    catch (final net.minidev.json.parser.ParseException e) {
      throw new IllegalArgumentException("The metadata of the OpenID Connect client '%s' of %s is not valid JSON - %s"
          .formatted(clientId, origin, e.getMessage()), e);
    }
    if (!(json instanceof final JSONObject object)) {
      throw new IllegalArgumentException("The metadata of the OpenID Connect client '%s' of %s is not a JSON object"
          .formatted(clientId, origin));
    }
    this.add(toClient(clientId, object, clientSecret, trustMarkTypes, origin), origin);
    return this;
  }

  /**
   * Gets the clients read, in the order they were given.
   *
   * @return the clients
   */
  public @NonNull List<OidcClientRecord> getClients() {
    return List.copyOf(this.clients);
  }

  /**
   * Adds a client, unless its identifier has already been given.
   *
   * @param client the client
   * @param origin where the client was given
   * @throws IllegalArgumentException if the client identifier has already been given
   */
  private void add(final @NonNull OidcClientRecord client, final @NonNull String origin) {
    final String previous = this.origins.putIfAbsent(client.clientId(), origin);
    if (previous != null) {
      throw new IllegalArgumentException("The OpenID Connect client '%s' is given more than once, in %s and in %s"
          .formatted(client.clientId(), previous, origin));
    }
    this.clients.add(client);
  }

  /**
   * Turns a client object of a resource into a client.
   *
   * @param object the client object
   * @param origin where the client was given
   * @return the client
   * @throws IllegalArgumentException for an invalid client
   */
  private static @NonNull OidcClientRecord toClient(final @NonNull JSONObject object, final @NonNull String origin) {
    if (!(object.get(CLIENT_ID) instanceof final String clientId) || clientId.isBlank()) {
      throw new IllegalArgumentException("A client of %s has no %s".formatted(origin, CLIENT_ID));
    }
    for (final String field : object.keySet()) {
      if (!FIELDS.contains(field)) {
        throw new IllegalArgumentException(
            "The OpenID Connect client '%s' of %s has the unknown field '%s' - the client metadata goes in '%s'"
                .formatted(clientId, origin, field, METADATA));
      }
    }
    if (!(object.get(METADATA) instanceof final JSONObject metadata)) {
      throw new IllegalArgumentException("The OpenID Connect client '%s' of %s has no %s object"
          .formatted(clientId, origin, METADATA));
    }
    final Object secret = object.get(CLIENT_SECRET);
    if (secret != null && !(secret instanceof String)) {
      throw new IllegalArgumentException("The %s of the OpenID Connect client '%s' of %s is not a string"
          .formatted(CLIENT_SECRET, clientId, origin));
    }
    final List<String> trustMarkTypes = new ArrayList<>();
    final Object types = object.get(TRUST_MARK_TYPES);
    if (types != null) {
      if (!(types instanceof final JSONArray array)) {
        throw new IllegalArgumentException("The %s of the OpenID Connect client '%s' of %s is not an array"
            .formatted(TRUST_MARK_TYPES, clientId, origin));
      }
      for (final Object type : array) {
        if (!(type instanceof final String value)) {
          throw new IllegalArgumentException(("The %s of the OpenID Connect client '%s' of %s holds a value that is "
              + "not a string").formatted(TRUST_MARK_TYPES, clientId, origin));
        }
        trustMarkTypes.add(value);
      }
    }
    return toClient(clientId, metadata, (String) secret, trustMarkTypes, origin);
  }

  /**
   * Creates a client from its parts, checking them.
   *
   * @param clientId the client identifier
   * @param metadata the client metadata
   * @param clientSecret the client secret, or {@code null}
   * @param trustMarkTypes the trust mark types, or {@code null}
   * @param origin where the client was given
   * @return the client
   * @throws IllegalArgumentException for an invalid client
   */
  private static @NonNull OidcClientRecord toClient(final @NonNull String clientId, final @NonNull JSONObject metadata,
      final @Nullable String clientSecret, final @Nullable Collection<String> trustMarkTypes,
      final @NonNull String origin) {

    if (metadata.containsKey(CLIENT_SECRET)) {
      throw new IllegalArgumentException(("The metadata of the OpenID Connect client '%s' of %s holds a %s - a client "
          + "secret is not client metadata, give it as client-secret of an inline client, or as the %s next to the "
          + "metadata in a file").formatted(clientId, origin, CLIENT_SECRET, CLIENT_SECRET));
    }
    final JSONObject json = new JSONObject(metadata);
    if (json.containsKey(CLIENT_ID)) {
      if (!clientId.equals(json.get(CLIENT_ID))) {
        throw new IllegalArgumentException(
            "The metadata of the OpenID Connect client '%s' of %s holds a different %s, '%s'"
                .formatted(clientId, origin, CLIENT_ID, json.get(CLIENT_ID)));
      }
      json.remove(CLIENT_ID);
    }
    if (clientSecret != null && clientSecret.isBlank()) {
      throw new IllegalArgumentException("The OpenID Connect client '%s' of %s has an empty client secret"
          .formatted(clientId, origin));
    }
    final Set<String> types = new LinkedHashSet<>();
    if (trustMarkTypes != null) {
      for (final String type : trustMarkTypes) {
        if (!StringUtils.hasText(type)) {
          throw new IllegalArgumentException("The OpenID Connect client '%s' of %s has an empty trust mark type"
              .formatted(clientId, origin));
        }
        types.add(type.trim());
      }
    }
    final OIDCClientMetadata clientMetadata;
    try {
      clientMetadata = OIDCClientMetadata.parse(json);
    }
    catch (final ParseException e) {
      throw new IllegalArgumentException("Invalid metadata for the OpenID Connect client '%s' of %s - %s"
          .formatted(clientId, origin, e.getMessage()), e);
    }
    if (clientSecret != null) {
      // The client secret is held as a custom field, see OidcClientRecord
      clientMetadata.setCustomField(CLIENT_SECRET, clientSecret);
    }
    return new OidcClientRecord(clientId, clientMetadata, types);
  }

}
