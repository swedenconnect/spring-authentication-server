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
package se.swedenconnect.spring.authnserver.service.config;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import org.jspecify.annotations.NonNull;
import org.springframework.core.io.Resource;
import org.springframework.util.StreamUtils;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import se.swedenconnect.spring.authnserver.oidc.client.OidcClientRecord;

/**
 * Reads statically configured OpenID Connect clients. Each location holds the client metadata of one client as a JSON
 * object, or a JSON array of such objects. The {@code client_id} of a client is given in its object, next to the
 * metadata parameters, and so is the {@code client_secret} of a client that authenticates with a secret.
 *
 * @author Martin Lindström
 */
public final class OidcClientLoader {

  /** The name of the parameter that holds the client ID. */
  public static final String CLIENT_ID = "client_id";

  /**
   * Reads the clients of the supplied locations.
   *
   * @param locations the locations
   * @return the clients
   * @throws IllegalArgumentException if a location cannot be read, does not hold valid client metadata, or a client is
   *     given more than once
   */
  public static @NonNull List<OidcClientRecord> load(final @NonNull List<Resource> locations) {
    Objects.requireNonNull(locations, "locations must not be null");
    final List<OidcClientRecord> clients = new ArrayList<>();
    final Set<String> clientIds = new HashSet<>();
    for (final Resource location : locations) {
      for (final OidcClientRecord client : load(location)) {
        if (!clientIds.add(client.clientId())) {
          throw new IllegalArgumentException("The OpenID Connect client '%s' is given more than once"
              .formatted(client.clientId()));
        }
        clients.add(client);
      }
    }
    return clients;
  }

  /**
   * Reads the clients of one location.
   *
   * @param location the location
   * @return the clients
   * @throws IllegalArgumentException if the location cannot be read or does not hold valid client metadata
   */
  public static @NonNull List<OidcClientRecord> load(final @NonNull Resource location) {
    final Object json;
    try (final InputStream is = location.getInputStream()) {
      json = new JSONParser(JSONParser.MODE_JSON_SIMPLE)
          .parse(StreamUtils.copyToString(is, StandardCharsets.UTF_8));
    }
    catch (final IOException | net.minidev.json.parser.ParseException e) {
      throw new IllegalArgumentException("Failed to read OpenID Connect clients from %s - %s"
          .formatted(location.getDescription(), e.getMessage()), e);
    }
    final List<OidcClientRecord> clients = new ArrayList<>();
    if (json instanceof final JSONObject object) {
      clients.add(toClient(object, location));
    }
    else if (json instanceof final JSONArray array) {
      for (final Object element : array) {
        if (!(element instanceof final JSONObject object)) {
          throw new IllegalArgumentException("%s holds an array element that is not a JSON object"
              .formatted(location.getDescription()));
        }
        clients.add(toClient(object, location));
      }
    }
    else {
      throw new IllegalArgumentException("%s does not hold a JSON object or array"
          .formatted(location.getDescription()));
    }
    return clients;
  }

  /**
   * Turns one JSON object into a client.
   *
   * @param object the JSON object
   * @param location the location, for error messages
   * @return the client
   * @throws IllegalArgumentException for an invalid client
   */
  private static @NonNull OidcClientRecord toClient(final @NonNull JSONObject object,
      final @NonNull Resource location) {
    if (!(object.get(CLIENT_ID) instanceof final String clientId) || clientId.isBlank()) {
      throw new IllegalArgumentException("A client of %s has no %s".formatted(location.getDescription(), CLIENT_ID));
    }
    final JSONObject metadata = new JSONObject(object);
    metadata.remove(CLIENT_ID);
    try {
      final OIDCClientMetadata clientMetadata = OIDCClientMetadata.parse(metadata);
      // The client secret is not a metadata parameter, and is not kept by the parsing
      if (object.get(OidcClientRecord.CLIENT_SECRET) instanceof final String secret) {
        clientMetadata.setCustomField(OidcClientRecord.CLIENT_SECRET, secret);
      }
      return OidcClientRecord.of(clientId, clientMetadata);
    }
    catch (final ParseException e) {
      throw new IllegalArgumentException("Invalid metadata for the OpenID Connect client '%s' of %s - %s"
          .formatted(clientId, location.getDescription(), e.getMessage()), e);
    }
  }

  // Hidden constructor
  private OidcClientLoader() {
  }

}
