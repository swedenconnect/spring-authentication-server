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
package se.swedenconnect.spring.authnserver.autoconfigure.actuate;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.function.Supplier;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.actuate.endpoint.Access;
import org.springframework.boot.actuate.endpoint.annotation.ReadOperation;
import org.springframework.boot.actuate.endpoint.annotation.Selector;
import org.springframework.boot.actuate.endpoint.annotation.WriteOperation;
import org.springframework.boot.actuate.endpoint.web.WebEndpointResponse;
import org.springframework.boot.actuate.endpoint.web.annotation.WebEndpoint;
import org.springframework.util.MimeType;

import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.autoconfigure.ConfiguredAuthnServer;
import se.swedenconnect.spring.authnserver.registry.ClientRegistryBackend;
import se.swedenconnect.spring.authnserver.registry.ClientUpdateResult;
import se.swedenconnect.spring.authnserver.registry.RegisteredClient;

/**
 * The {@value #ID} Actuator endpoint: the clients that the client registry holds, for both protocols.
 * <p>
 * The client identifier is a query parameter, since identifiers are usually URLs:
 * </p>
 * <ul>
 * <li>{@code GET /clients} lists every client.</li>
 * <li>{@code GET /clients/saml?id=...} and {@code GET /clients/oidc?id=...} show one client, and the path of its
 * metadata.</li>
 * <li>{@code GET /clients/saml/metadata?id=...} gives the {@code EntityDescriptor} of a Service Provider as XML, and
 * {@code GET /clients/oidc/metadata?id=...} the metadata of an OpenID Connect client as JSON.</li>
 * <li>{@code POST /clients/saml} updates every SAML metadata source that can be updated.</li>
 * <li>{@code POST /clients/oidc?id=...} drops an OpenID Federation client from the cache and resolves it again.</li>
 * </ul>
 * <p>
 * An unknown protocol or client gives 404. The update operations change state and make outgoing calls, so the default
 * access of the endpoint is read-only; they are available only when the deployment grants
 * {@code management.endpoint.clients.access: unrestricted}.
 * </p>
 *
 * @author Martin Lindström
 */
@WebEndpoint(id = ClientsEndpoint.ID, defaultAccess = Access.READ_ONLY)
public class ClientsEndpoint {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(ClientsEndpoint.class);

  /** The endpoint id. */
  public static final String ID = "clients";

  /** The media type of SAML metadata. */
  public static final String SAML_METADATA_MEDIA_TYPE = "application/samlmetadata+xml";

  /** The selector value for the metadata of a client. */
  public static final String METADATA = "metadata";

  /** The configured server. */
  private final ConfiguredAuthnServer server;

  /** Gives the path of the endpoint. */
  private final Supplier<String> endpointPath;

  /**
   * Constructor.
   *
   * @param server the configured server
   * @param endpointPath gives the path of the endpoint, such as {@code /actuator/clients}
   */
  public ClientsEndpoint(final @NonNull ConfiguredAuthnServer server, final @NonNull Supplier<String> endpointPath) {
    this.server = Objects.requireNonNull(server, "server must not be null");
    this.endpointPath = Objects.requireNonNull(endpointPath, "endpointPath must not be null");
  }

  /**
   * Lists every client.
   *
   * @return a map holding the list of clients
   */
  @ReadOperation
  public @NonNull Map<String, Object> clients() {
    final List<Map<String, Object>> clients = new ArrayList<>();
    for (final ClientRegistryBackend backend : this.server.getClientRegistryBackends()) {
      backend.getClients().forEach(c -> clients.add(toMap(c, false)));
    }
    return Map.of("clients", clients);
  }

  /**
   * Shows one client.
   *
   * @param protocol the protocol, {@code saml} or {@code oidc}
   * @param id the identity of the client
   * @return the client and the path of its metadata, or 404 if the client is not known
   */
  @ReadOperation
  public @NonNull WebEndpointResponse<Map<String, Object>> client(final @Selector @NonNull String protocol,
      final @NonNull String id) {
    final AuthenticationProtocol p = parseProtocol(protocol);
    if (p == null) {
      return new WebEndpointResponse<>(WebEndpointResponse.STATUS_NOT_FOUND);
    }
    for (final ClientRegistryBackend backend : this.backends(p)) {
      final RegisteredClient client = backend.getClient(id);
      if (client != null) {
        final Map<String, Object> result = toMap(client, true);
        result.put("metadata", "%s/%s/%s?id=%s".formatted(this.endpointPath.get(), protocol(p), METADATA,
            URLEncoder.encode(id, StandardCharsets.UTF_8)));
        return new WebEndpointResponse<>(result);
      }
    }
    return new WebEndpointResponse<>(WebEndpointResponse.STATUS_NOT_FOUND);
  }

  /**
   * Gives the metadata of one client, exactly as held: XML for SAML and JSON for OpenID Connect.
   *
   * @param protocol the protocol, {@code saml} or {@code oidc}
   * @param metadata the literal {@value #METADATA}
   * @param id the identity of the client
   * @return the metadata, or 404 if the client is not known
   */
  @ReadOperation(produces = { SAML_METADATA_MEDIA_TYPE, "application/xml", "application/json" })
  public @NonNull WebEndpointResponse<String> metadata(final @Selector @NonNull String protocol,
      final @Selector @NonNull String metadata, final @NonNull String id) {
    final AuthenticationProtocol p = parseProtocol(protocol);
    if (p == null || !METADATA.equals(metadata)) {
      return new WebEndpointResponse<>(WebEndpointResponse.STATUS_NOT_FOUND);
    }
    for (final ClientRegistryBackend backend : this.backends(p)) {
      final String document = backend.getMetadata(id);
      if (document != null) {
        return new WebEndpointResponse<>(document, WebEndpointResponse.STATUS_OK,
            MimeType.valueOf(p == AuthenticationProtocol.SAML ? SAML_METADATA_MEDIA_TYPE : "application/json"));
      }
    }
    return new WebEndpointResponse<>(WebEndpointResponse.STATUS_NOT_FOUND);
  }

  /**
   * Updates client data. For SAML every metadata source that can be updated is updated, and no client is named. For
   * OpenID Connect the named client is fetched again; a client from the configuration or a repository has nothing to
   * update.
   *
   * @param protocol the protocol, {@code saml} or {@code oidc}
   * @param id the identity of the client, required for OpenID Connect and not used for SAML
   * @return the result, 404 if the protocol or the client is not known, and 502 if the update failed
   */
  @WriteOperation
  public @NonNull WebEndpointResponse<Map<String, Object>> update(final @Selector @NonNull String protocol,
      final @Nullable String id) {
    final AuthenticationProtocol p = parseProtocol(protocol);
    if (p == null) {
      return new WebEndpointResponse<>(WebEndpointResponse.STATUS_NOT_FOUND);
    }
    final List<ClientRegistryBackend> backends = this.backends(p);
    if (backends.isEmpty()) {
      return new WebEndpointResponse<>(WebEndpointResponse.STATUS_NOT_FOUND);
    }
    if (p == AuthenticationProtocol.SAML) {
      log.debug("Request to update the SAML metadata sources received");
      final List<ClientUpdateResult> results = backends.stream().map(ClientRegistryBackend::update).toList();
      return toResponse(p, null, combine(results));
    }
    if (id == null || id.isBlank()) {
      return new WebEndpointResponse<>(Map.of("error", "The client must be given with the id parameter"),
          WebEndpointResponse.STATUS_BAD_REQUEST);
    }
    for (final ClientRegistryBackend backend : backends) {
      if (backend.getClient(id) != null) {
        log.debug("Request to update the client '{}' received", id);
        return toResponse(p, id, backend.update(id));
      }
    }
    return new WebEndpointResponse<>(WebEndpointResponse.STATUS_NOT_FOUND);
  }

  /**
   * Gets the backends of a protocol.
   *
   * @param protocol the protocol
   * @return the backends
   */
  private @NonNull List<ClientRegistryBackend> backends(final @NonNull AuthenticationProtocol protocol) {
    return this.server.getClientRegistryBackends().stream()
        .filter(b -> b.getProtocol() == protocol)
        .toList();
  }

  /**
   * Combines the results of several backends: a failure if any failed, an update if any updated, and otherwise nothing
   * to update.
   *
   * @param results the results
   * @return the combined result
   */
  private static @NonNull ClientUpdateResult combine(final @NonNull List<ClientUpdateResult> results) {
    if (results.size() == 1) {
      return results.get(0);
    }
    final String message = String.join("; ", results.stream().map(ClientUpdateResult::message).toList());
    for (final ClientUpdateResult.Outcome outcome : List.of(ClientUpdateResult.Outcome.FAILED,
        ClientUpdateResult.Outcome.UPDATED)) {
      if (results.stream().anyMatch(r -> r.outcome() == outcome)) {
        return new ClientUpdateResult(outcome, message);
      }
    }
    return ClientUpdateResult.nothingToUpdate(message);
  }

  /**
   * Creates the response of an update.
   *
   * @param protocol the protocol
   * @param id the client, or {@code null}
   * @param result the result
   * @return the response, with status 502 if the update failed
   */
  private static @NonNull WebEndpointResponse<Map<String, Object>> toResponse(
      final @NonNull AuthenticationProtocol protocol, final @Nullable String id,
      final @NonNull ClientUpdateResult result) {
    final Map<String, Object> body = new LinkedHashMap<>();
    body.put("protocol", protocol(protocol));
    if (id != null) {
      body.put("id", id);
    }
    body.put("outcome", result.outcome().name().toLowerCase(Locale.ROOT).replace('_', '-'));
    body.put("message", result.message());
    return new WebEndpointResponse<>(body,
        result.outcome() == ClientUpdateResult.Outcome.FAILED ? 502 : WebEndpointResponse.STATUS_OK);
  }

  /**
   * Creates the JSON object of a client.
   *
   * @param client the client
   * @param details whether the marks are included
   * @return the JSON object
   */
  private static @NonNull Map<String, Object> toMap(final @NonNull RegisteredClient client, final boolean details) {
    final Map<String, Object> map = new LinkedHashMap<>();
    map.put("protocol", protocol(client.requester().protocol()));
    map.put("id", client.requester().identifier());
    if (client.organizationNumber() != null) {
      map.put("organization-number", client.organizationNumber());
    }
    if (details) {
      map.put("marks", client.marks().stream().sorted().toList());
    }
    map.put("source", client.source());
    if (client.expiresAt() != null) {
      map.put("expires-at", client.expiresAt().toString());
    }
    return map;
  }

  /**
   * Parses the protocol of a path.
   *
   * @param protocol the protocol, {@code saml} or {@code oidc}
   * @return the protocol, or {@code null} if not known
   */
  private static @Nullable AuthenticationProtocol parseProtocol(final @NonNull String protocol) {
    for (final AuthenticationProtocol p : AuthenticationProtocol.values()) {
      if (p.name().equalsIgnoreCase(protocol)) {
        return p;
      }
    }
    return null;
  }

  /**
   * Gets the name of a protocol as it is used in paths and output.
   *
   * @param protocol the protocol
   * @return the name
   */
  private static @NonNull String protocol(final @NonNull AuthenticationProtocol protocol) {
    return protocol.name().toLowerCase(Locale.ROOT);
  }

}
