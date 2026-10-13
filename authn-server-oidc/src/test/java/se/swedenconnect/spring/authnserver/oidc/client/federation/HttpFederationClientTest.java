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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.tuple;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.openid.connect.sdk.federation.entities.EntityID;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import se.swedenconnect.oidf.common.entity.entity.integration.federation.EntityConfigurationRequest;
import se.swedenconnect.oidf.common.entity.entity.integration.federation.FederationRequest;
import se.swedenconnect.oidf.common.entity.entity.integration.federation.FederationTrustMarkStatusRequest;
import se.swedenconnect.oidf.common.entity.entity.integration.federation.ResolveRequest;
import se.swedenconnect.oidf.common.entity.entity.integration.federation.TrustMarkRequest;
import se.swedenconnect.oidf.common.entity.entity.integration.trustmark.TrustMarkStatusResponse;
import se.swedenconnect.spring.authnserver.registry.ClientRegistryException;

/**
 * Tests for {@link HttpFederationClient}.
 *
 * @author Martin Lindström
 */
class HttpFederationClientTest extends FederationTestSupport {

  /** The HTTP server of the test. */
  private HttpServer server;

  /** The queries that the server was called with. */
  private final List<String> queries = new ArrayList<>();

  /** The paths that the server was called with. */
  private final List<String> paths = new ArrayList<>();

  /** The methods and bodies that the server was called with. */
  private final List<String> requests = new ArrayList<>();

  /** The responses that the client received, when made with {@link #recordingClient()}. */
  private final List<RecordedResponse> responses = new ArrayList<>();

  /** What the server answers. */
  private int status = 200;

  /** The body that the server answers with. */
  private String body = "";

  @AfterEach
  void stopServer() {
    if (this.server != null) {
      this.server.stop(0);
      this.server = null;
    }
  }

  @Test
  void theResolveRequestCarriesTheSubjectTheTrustAnchorAndTheEntityType() throws Exception {
    final ECKey key = key("k1");
    final SignedJWT response = resolveResponse(key, RESOLVER, CLIENT_ID, clientMetadata("The Client"),
        Set.of(), Instant.now().plus(1, ChronoUnit.HOURS));
    this.body = response.serialize();
    final int port = this.startServer();

    final SignedJWT answer = new HttpFederationClient().resolve(new FederationRequest<>(
        new ResolveRequest(CLIENT_ID, TRUST_ANCHOR, List.of("openid_relying_party"), Boolean.FALSE),
        Map.of(HttpFederationClient.FEDERATION_RESOLVE_ENDPOINT,
            "http://localhost:%d/resolve".formatted(port))));

    assertThat(answer).isNotNull();
    assertThat(answer.serialize()).isEqualTo(this.body);
    assertThat(this.queries).hasSize(1);
    assertThat(this.queries.get(0))
        .contains("sub=https%3A%2F%2Fclient.example.com")
        .contains("trust_anchor=https%3A%2F%2Fta.example.com")
        .contains("entity_type=openid_relying_party");
  }

  @Test
  void eachEntityTypeIsSentAsAParameterOfItsOwn() throws Exception {
    final ECKey key = key("k1");
    this.body = resolveResponse(key, RESOLVER, CLIENT_ID, clientMetadata("The Client"),
        Set.of(), Instant.now().plus(1, ChronoUnit.HOURS)).serialize();
    final int port = this.startServer();

    new HttpFederationClient().resolve(new FederationRequest<>(
        new ResolveRequest(CLIENT_ID, TRUST_ANCHOR, List.of("openid_relying_party", "federation_entity"),
            Boolean.FALSE),
        Map.of(HttpFederationClient.FEDERATION_RESOLVE_ENDPOINT, "http://localhost:%d/resolve".formatted(port))));

    assertThat(this.queries).hasSize(1);
    assertThat(this.queries.get(0))
        .contains("entity_type=openid_relying_party&entity_type=federation_entity");
  }

  @Test
  void noEntityTypeParameterIsSentWithoutTypes() throws Exception {
    final ECKey key = key("k1");
    this.body = resolveResponse(key, RESOLVER, CLIENT_ID, clientMetadata("The Client"),
        Set.of(), Instant.now().plus(1, ChronoUnit.HOURS)).serialize();
    final int port = this.startServer();

    new HttpFederationClient().resolve(this.resolveRequest(port));

    assertThat(this.queries).hasSize(1);
    assertThat(this.queries.get(0)).doesNotContain("entity_type");
  }

  @Test
  void theTrustMarkRequestCarriesTheTypeAndTheSubject() throws Exception {
    final ECKey key = key("k1");
    this.body = trustMark(key, TRUST_MARK_ISSUER, CLIENT_ID, MARK_ONE, null).serialize();
    final int port = this.startServer();

    final SignedJWT answer = new HttpFederationClient().trustMark(new FederationRequest<>(
        new TrustMarkRequest(new EntityID(CLIENT_ID), new EntityID(TRUST_MARK_ISSUER), new EntityID(MARK_ONE)),
        Map.of(HttpFederationClient.FEDERATION_TRUST_MARK_ENDPOINT,
            "http://localhost:%d/trust_mark".formatted(port))));

    assertThat(answer).isNotNull();
    assertThat(this.queries.get(0))
        .contains("trust_mark_type=https%3A%2F%2Fexample.com%2Fmark-one")
        .contains("sub=https%3A%2F%2Fclient.example.com");
  }

  @Test
  void theTrustMarkStatusRequestPostsTheTrustMark() throws Exception {
    final ECKey key = key("k1");
    final String trustMark = trustMark(key, TRUST_MARK_ISSUER, CLIENT_ID, MARK_ONE, null).serialize();
    this.body = trustMarkStatus(key, TRUST_MARK_ISSUER, trustMark, "active").serialize();
    final int port = this.startServer();

    final TrustMarkStatusResponse answer = new HttpFederationClient().trustMarkStatus(new FederationRequest<>(
        new FederationTrustMarkStatusRequest(trustMark, TRUST_MARK_ISSUER),
        Map.of(HttpFederationClient.FEDERATION_TRUST_MARK_STATUS_ENDPOINT,
            "http://localhost:%d/trust_mark_status".formatted(port))));

    assertThat(answer.isError()).isFalse();
    assertThat(answer.getSignedJWT().serialize()).isEqualTo(this.body);
    assertThat(this.requests).containsExactly("POST trust_mark=" + trustMark);
  }

  @Test
  void aTrustMarkStatusEndpointThatAnswersNotFoundIsAnError() throws Exception {
    this.status = 404;
    final int port = this.startServer();

    assertThatThrownBy(() -> new HttpFederationClient().trustMarkStatus(new FederationRequest<>(
        new FederationTrustMarkStatusRequest("a.b.c", TRUST_MARK_ISSUER),
        Map.of(HttpFederationClient.FEDERATION_TRUST_MARK_STATUS_ENDPOINT,
            "http://localhost:%d/trust_mark_status".formatted(port)))))
        .isInstanceOf(ClientRegistryException.class)
        .hasMessageContaining("404");
  }

  @Test
  void anEndpointThatAnswersNotFoundGivesNothing() throws Exception {
    this.status = 404;
    final int port = this.startServer();

    assertThat(new HttpFederationClient().resolve(this.resolveRequest(port))).isNull();
  }

  @Test
  void anEndpointThatFailsIsAnError() throws Exception {
    this.status = 500;
    this.body = "server error";
    final int port = this.startServer();

    assertThatThrownBy(() -> new HttpFederationClient().resolve(this.resolveRequest(port)))
        .isInstanceOf(ClientRegistryException.class)
        .hasMessageContaining("500");
  }

  @Test
  void anEndpointThatDoesNotAnswerWithASignedJwtIsAnError() throws Exception {
    this.body = "not a jwt";
    final int port = this.startServer();

    assertThatThrownBy(() -> new HttpFederationClient().resolve(this.resolveRequest(port)))
        .isInstanceOf(ClientRegistryException.class)
        .hasMessageContaining("signed JWT");
  }

  @Test
  void anEndpointThatAnswersWithAnEmptyBodyIsAnError() throws Exception {
    final int port = this.startServer();

    assertThatThrownBy(() -> new HttpFederationClient().resolve(this.resolveRequest(port)))
        .isInstanceOf(ClientRegistryException.class)
        .hasMessageContaining("empty body");
  }

  @Test
  void anEndpointThatCannotBeReachedIsAnError() {
    assertThatThrownBy(() -> new HttpFederationClient().resolve(new FederationRequest<>(
        new ResolveRequest(CLIENT_ID, TRUST_ANCHOR, null, Boolean.FALSE),
        Map.of(HttpFederationClient.FEDERATION_RESOLVE_ENDPOINT, "http://localhost:1/resolve"))))
        .isInstanceOf(ClientRegistryException.class);
  }

  @Test
  void everyCallIsPublishedWithItsOutcome() throws Exception {
    final List<FederationCallEvent> events = new ArrayList<>();
    final HttpFederationClient client = new HttpFederationClient();
    client.setApplicationEventPublisher(e -> events.add((FederationCallEvent) e));
    final int port = this.startServer();

    this.status = 404;
    assertThat(client.resolve(this.resolveRequest(port))).isNull();
    this.status = 500;
    this.body = "server error";
    assertThatThrownBy(() -> client.resolve(this.resolveRequest(port))).isInstanceOf(ClientRegistryException.class);
    assertThatThrownBy(() -> client.resolve(new FederationRequest<>(
        new ResolveRequest(CLIENT_ID, TRUST_ANCHOR, null, Boolean.FALSE),
        Map.of(HttpFederationClient.FEDERATION_RESOLVE_ENDPOINT, "http://localhost:1/resolve"))))
        .isInstanceOf(ClientRegistryException.class);
    this.status = 200;
    this.body = trustMark(key("k1"), TRUST_MARK_ISSUER, CLIENT_ID, MARK_ONE, null).serialize();
    client.trustMark(new FederationRequest<>(
        new TrustMarkRequest(new EntityID(CLIENT_ID), new EntityID(TRUST_MARK_ISSUER), new EntityID(MARK_ONE)),
        Map.of(HttpFederationClient.FEDERATION_TRUST_MARK_ENDPOINT,
            "http://localhost:%d/trust_mark".formatted(port))));
    this.status = 404;
    this.body = "";
    assertThatThrownBy(() -> client.trustMarkStatus(new FederationRequest<>(
        new FederationTrustMarkStatusRequest("a.b.c", TRUST_MARK_ISSUER),
        Map.of(HttpFederationClient.FEDERATION_TRUST_MARK_STATUS_ENDPOINT,
            "http://localhost:%d/trust_mark_status".formatted(port))))).isInstanceOf(ClientRegistryException.class);

    assertThat(events).extracting(FederationCallEvent::getCall, FederationCallEvent::getOutcome).containsExactly(
        tuple(FederationCallEvent.Call.RESOLVE, FederationCallEvent.Outcome.SUCCESS),
        tuple(FederationCallEvent.Call.RESOLVE, FederationCallEvent.Outcome.ERROR_RESPONSE),
        tuple(FederationCallEvent.Call.RESOLVE, FederationCallEvent.Outcome.UNREACHABLE),
        tuple(FederationCallEvent.Call.TRUST_MARK, FederationCallEvent.Outcome.SUCCESS),
        tuple(FederationCallEvent.Call.TRUST_MARK_STATUS, FederationCallEvent.Outcome.ERROR_RESPONSE));
    assertThat(events.get(0).getServiceType()).isEqualTo(FederationCallEvent.ServiceType.RESOLVER);
    assertThat(events.get(0).getServiceId()).isEqualTo("http://localhost:%d/resolve".formatted(port));
    assertThat(events.get(0).getError()).isNull();
    assertThat(events.get(1).getError()).contains("500");
    assertThat(events.get(3).getServiceType()).isEqualTo(FederationCallEvent.ServiceType.TRUST_MARK_ISSUER);
    assertThat(events.get(3).getServiceId()).isEqualTo(TRUST_MARK_ISSUER);
    assertThat(events.get(3).getIssuer()).isEqualTo(TRUST_MARK_ISSUER);
    assertThat(events.get(4).getServiceId()).isEqualTo(TRUST_MARK_ISSUER);
    assertThat(events.get(4).getEndpoint()).endsWith("/trust_mark_status");
    assertThat(events.get(4).getTime()).isNotNull();
  }

  @Test
  void aPublisherThatFailsDoesNotAffectTheCall() throws Exception {
    this.status = 404;
    final int port = this.startServer();
    final HttpFederationClient client = new HttpFederationClient();
    client.setApplicationEventPublisher(e -> {
      throw new IllegalStateException("no listeners");
    });
    assertThat(client.resolve(this.resolveRequest(port))).isNull();
  }

  @Test
  void aRequestWithoutAnEndpointIsAnError() {
    assertThatThrownBy(() -> new HttpFederationClient().resolve(new FederationRequest<>(
        new ResolveRequest(CLIENT_ID, TRUST_ANCHOR, null, Boolean.FALSE), Map.of())))
        .isInstanceOf(ClientRegistryException.class)
        .hasMessageContaining(HttpFederationClient.FEDERATION_RESOLVE_ENDPOINT);
  }

  @Test
  void theEntityConfigurationIsFetchedFromTheWellKnownLocation() throws Exception {
    final ECKey key = key("k1");
    final int port = this.startServer();
    final String entityId = "http://localhost:%d/ta/".formatted(port);
    this.body = entityConfiguration(key, entityId, Map.of(), Instant.now().plus(1, ChronoUnit.HOURS)).serialize();
    final List<FederationCallEvent> events = new ArrayList<>();
    final HttpFederationClient client = new HttpFederationClient();
    client.setApplicationEventPublisher(e -> events.add((FederationCallEvent) e));

    final SignedJWT answer = client.entityConfiguration(new FederationRequest<>(
        new EntityConfigurationRequest(new EntityID(entityId), null)));

    assertThat(answer.serialize()).isEqualTo(this.body);
    assertThat(this.paths).containsExactly("/ta/.well-known/openid-federation");
    assertThat(events).singleElement().satisfies(e -> {
      assertThat(e.getCall()).isEqualTo(FederationCallEvent.Call.ENTITY_CONFIGURATION);
      assertThat(e.getServiceType()).isEqualTo(FederationCallEvent.ServiceType.ENTITY_CONFIGURATION);
      assertThat(e.getServiceId()).isEqualTo(entityId);
      assertThat(e.getOutcome()).isEqualTo(FederationCallEvent.Outcome.SUCCESS);
    });
  }

  @Test
  void anEntityConfigurationThatIsNotFoundIsAnError() throws Exception {
    this.status = 404;
    final int port = this.startServer();
    final String entityId = "http://localhost:%d".formatted(port);
    assertThatThrownBy(() -> new HttpFederationClient().entityConfiguration(new FederationRequest<>(
        new EntityConfigurationRequest(new EntityID(entityId), null))))
        .isInstanceOf(ClientRegistryException.class)
        .hasMessageContaining("404");
  }

  @Test
  void theCallsThatTheClientRegistryDoesNotMakeAreNotImplemented() {
    final HttpFederationClient client = new HttpFederationClient();
    assertThatThrownBy(() -> client.fetch(null)).isInstanceOf(UnsupportedOperationException.class);
    assertThatThrownBy(() -> client.subordinateListing(null)).isInstanceOf(UnsupportedOperationException.class);
    assertThatThrownBy(() -> client.trustMarkedListing(null)).isInstanceOf(UnsupportedOperationException.class);
  }

  @Test
  void theResponseIsClosedAfterASuccessfulResolve() throws Exception {
    this.body = resolveResponse(key("k1"), RESOLVER, CLIENT_ID, clientMetadata("The Client"),
        Set.of(), Instant.now().plus(1, ChronoUnit.HOURS)).serialize();
    final int port = this.startServer();

    assertThat(this.recordingClient().resolve(this.resolveRequest(port))).isNotNull();
    this.assertEveryResponseClosed(1);
  }

  @Test
  void theResponseIsClosedAfterASuccessfulTrustMarkRequest() throws Exception {
    this.body = trustMark(key("k1"), TRUST_MARK_ISSUER, CLIENT_ID, MARK_ONE, null).serialize();
    final int port = this.startServer();

    assertThat(this.recordingClient().trustMark(this.trustMarkRequest(port))).isNotNull();
    this.assertEveryResponseClosed(1);
  }

  @Test
  void theResponseIsClosedAfterASuccessfulTrustMarkStatusRequest() throws Exception {
    final ECKey key = key("k1");
    final String trustMark = trustMark(key, TRUST_MARK_ISSUER, CLIENT_ID, MARK_ONE, null).serialize();
    this.body = trustMarkStatus(key, TRUST_MARK_ISSUER, trustMark, "active").serialize();
    final int port = this.startServer();

    assertThat(this.recordingClient().trustMarkStatus(this.trustMarkStatusRequest(trustMark, port)).isError())
        .isFalse();
    this.assertEveryResponseClosed(1);
  }

  @Test
  void theResponseIsClosedAfterASuccessfulEntityConfigurationRequest() throws Exception {
    final int port = this.startServer();
    final String entityId = "http://localhost:%d".formatted(port);
    this.body = entityConfiguration(key("k1"), entityId, Map.of(), Instant.now().plus(1, ChronoUnit.HOURS))
        .serialize();

    assertThat(this.recordingClient().entityConfiguration(this.entityConfigurationRequest(entityId))).isNotNull();
    this.assertEveryResponseClosed(1);
  }

  @Test
  void theResponseIsClosedWhenAResolveRequestIsAnsweredNotFound() throws Exception {
    this.status = 404;
    this.body = "not found";
    final int port = this.startServer();

    assertThat(this.recordingClient().resolve(this.resolveRequest(port))).isNull();
    this.assertEveryResponseClosed(1);
  }

  @Test
  void theResponseIsClosedWhenATrustMarkRequestIsAnsweredNotFound() throws Exception {
    this.status = 404;
    final int port = this.startServer();

    assertThat(this.recordingClient().trustMark(this.trustMarkRequest(port))).isNull();
    this.assertEveryResponseClosed(1);
  }

  @Test
  void theResponseIsClosedWhenATrustMarkStatusRequestIsAnsweredNotFound() throws Exception {
    this.status = 404;
    this.body = "not found";
    final int port = this.startServer();

    assertThatThrownBy(() -> this.recordingClient().trustMarkStatus(this.trustMarkStatusRequest("a.b.c", port)))
        .isInstanceOf(ClientRegistryException.class)
        .hasMessageContaining("404");
    this.assertEveryResponseClosed(1);
  }

  @Test
  void theResponseIsClosedWhenAnEntityConfigurationRequestIsAnsweredNotFound() throws Exception {
    this.status = 404;
    final int port = this.startServer();

    assertThatThrownBy(() -> this.recordingClient().entityConfiguration(
        this.entityConfigurationRequest("http://localhost:%d".formatted(port))))
        .isInstanceOf(ClientRegistryException.class)
        .hasMessageContaining("404");
    this.assertEveryResponseClosed(1);
  }

  @Test
  void theResponseIsClosedWhenTheEndpointAnswersWithAnotherError() throws Exception {
    this.status = 500;
    this.body = "server error";
    final int port = this.startServer();

    assertThatThrownBy(() -> this.recordingClient().resolve(this.resolveRequest(port)))
        .isInstanceOf(ClientRegistryException.class)
        .hasMessageContaining("500");
    this.assertEveryResponseClosed(1);
  }

  @Test
  void theResponseIsClosedWhenTheEndpointAnswersWithAClientError() throws Exception {
    this.status = 400;
    final int port = this.startServer();

    assertThatThrownBy(() -> this.recordingClient().trustMarkStatus(this.trustMarkStatusRequest("a.b.c", port)))
        .isInstanceOf(ClientRegistryException.class)
        .hasMessageContaining("400");
    this.assertEveryResponseClosed(1);
  }

  @Test
  void theResponseIsClosedWhenTheEndpointAnswersWithAnEmptyBody() throws Exception {
    final int port = this.startServer();

    assertThatThrownBy(() -> this.recordingClient().resolve(this.resolveRequest(port)))
        .isInstanceOf(ClientRegistryException.class)
        .hasMessageContaining("empty body");
    this.assertEveryResponseClosed(1);
  }

  @Test
  void theResponseIsClosedWhenTheEndpointAnswersWithABlankBody() throws Exception {
    this.body = "  \n ";
    final int port = this.startServer();

    assertThatThrownBy(() -> this.recordingClient().trustMark(this.trustMarkRequest(port)))
        .isInstanceOf(ClientRegistryException.class)
        .hasMessageContaining("empty body");
    this.assertEveryResponseClosed(1);
  }

  @Test
  void theResponseIsClosedWhenTheEndpointDoesNotAnswerWithASignedJwt() throws Exception {
    this.body = "not a jwt";
    final int port = this.startServer();

    assertThatThrownBy(() -> this.recordingClient().resolve(this.resolveRequest(port)))
        .isInstanceOf(ClientRegistryException.class)
        .hasMessageContaining("signed JWT");
    this.assertEveryResponseClosed(1);
  }

  @Test
  void everyResponseIsClosedOverManyCallsWithTheSameClient() throws Exception {
    final HttpFederationClient client = this.recordingClient();
    final int port = this.startServer();
    final int calls = 20;

    for (int i = 0; i < calls; i++) {
      this.status = 404;
      this.body = "";
      assertThat(client.trustMark(this.trustMarkRequest(port))).isNull();
      this.status = 500;
      this.body = "server error";
      assertThatThrownBy(() -> client.resolve(this.resolveRequest(port)))
          .isInstanceOf(ClientRegistryException.class);
    }
    this.assertEveryResponseClosed(2 * calls);
  }

  @Test
  void noResponseIsRecordedWhenTheEndpointCannotBeReached() {
    assertThatThrownBy(() -> this.recordingClient().resolve(new FederationRequest<>(
        new ResolveRequest(CLIENT_ID, TRUST_ANCHOR, null, Boolean.FALSE),
        Map.of(HttpFederationClient.FEDERATION_RESOLVE_ENDPOINT, "http://localhost:1/resolve"))))
        .isInstanceOf(ClientRegistryException.class);
    assertThat(this.responses).isEmpty();
  }

  private FederationRequest<ResolveRequest> resolveRequest(final int port) {
    return new FederationRequest<>(new ResolveRequest(CLIENT_ID, TRUST_ANCHOR, null, Boolean.FALSE),
        Map.of(HttpFederationClient.FEDERATION_RESOLVE_ENDPOINT,
            URI.create("http://localhost:%d/resolve".formatted(port)).toString()));
  }

  private FederationRequest<TrustMarkRequest> trustMarkRequest(final int port) {
    return new FederationRequest<>(
        new TrustMarkRequest(new EntityID(CLIENT_ID), new EntityID(TRUST_MARK_ISSUER), new EntityID(MARK_ONE)),
        Map.of(HttpFederationClient.FEDERATION_TRUST_MARK_ENDPOINT, "http://localhost:%d/trust_mark".formatted(port)));
  }

  private FederationRequest<FederationTrustMarkStatusRequest> trustMarkStatusRequest(
      final String trustMark, final int port) {
    return new FederationRequest<>(new FederationTrustMarkStatusRequest(trustMark, TRUST_MARK_ISSUER),
        Map.of(HttpFederationClient.FEDERATION_TRUST_MARK_STATUS_ENDPOINT,
            "http://localhost:%d/trust_mark_status".formatted(port)));
  }

  private FederationRequest<EntityConfigurationRequest> entityConfigurationRequest(final String entityId) {
    return new FederationRequest<>(new EntityConfigurationRequest(new EntityID(entityId), null));
  }

  /**
   * Creates a client whose {@link RestClient} records every response it receives in {@link #responses}.
   *
   * @return the client
   */
  private HttpFederationClient recordingClient() {
    return new HttpFederationClient(RestClient.builder()
        .requestFactory(new RecordingRequestFactory(new SimpleClientHttpRequestFactory(), this.responses))
        .build());
  }

  /**
   * Asserts that the client received the given number of responses and closed every one of them.
   *
   * @param expected the expected number of responses
   */
  private void assertEveryResponseClosed(final int expected) {
    assertThat(this.responses).hasSize(expected).allSatisfy(r -> assertThat(r.isClosed())
        .as("response %s was closed", r.getStatusCode())
        .isTrue());
  }

  /**
   * Starts an HTTP server that records the query and answers with the configured status and body.
   *
   * @return the port that the server listens on
   * @throws IOException if the server cannot be started
   */
  private int startServer() throws IOException {
    this.server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
    this.server.createContext("/", this::handle);
    this.server.start();
    return this.server.getAddress().getPort();
  }

  private void handle(final HttpExchange exchange) throws IOException {
    this.queries.add(exchange.getRequestURI().getRawQuery());
    this.paths.add(exchange.getRequestURI().getPath());
    this.requests.add(exchange.getRequestMethod() + " "
        + new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
    final byte[] bytes = this.body.getBytes(StandardCharsets.UTF_8);
    if (bytes.length == 0) {
      exchange.sendResponseHeaders(this.status, -1);
      exchange.close();
      return;
    }
    exchange.sendResponseHeaders(this.status, bytes.length);
    try (final OutputStream out = exchange.getResponseBody()) {
      out.write(bytes);
    }
  }

  /**
   * A request factory that wraps a real one and records every response that its requests receive.
   */
  private record RecordingRequestFactory(ClientHttpRequestFactory delegate, List<RecordedResponse> responses)
      implements ClientHttpRequestFactory {

    @Override
    public ClientHttpRequest createRequest(final URI uri, final HttpMethod httpMethod) throws IOException {
      final ClientHttpRequest request = this.delegate.createRequest(uri, httpMethod);
      return new ClientHttpRequest() {

        @Override
        public ClientHttpResponse execute() throws IOException {
          final RecordedResponse response = new RecordedResponse(request.execute());
          RecordingRequestFactory.this.responses.add(response);
          return response;
        }

        @Override
        public OutputStream getBody() throws IOException {
          return request.getBody();
        }

        @Override
        public HttpMethod getMethod() {
          return request.getMethod();
        }

        @Override
        public URI getURI() {
          return request.getURI();
        }

        @Override
        public Map<String, Object> getAttributes() {
          return request.getAttributes();
        }

        @Override
        public HttpHeaders getHeaders() {
          return request.getHeaders();
        }
      };
    }
  }

  /**
   * A response that records whether it was closed.
   */
  private static class RecordedResponse implements ClientHttpResponse {

    /** The real response. */
    private final ClientHttpResponse delegate;

    /** The status of the response, read when it was received. */
    private final HttpStatusCode statusCode;

    /** Whether the response was closed. */
    private boolean closed;

    RecordedResponse(final ClientHttpResponse delegate) throws IOException {
      this.delegate = delegate;
      this.statusCode = delegate.getStatusCode();
    }

    boolean isClosed() {
      return this.closed;
    }

    @Override
    public HttpStatusCode getStatusCode() {
      return this.statusCode;
    }

    @Override
    public String getStatusText() throws IOException {
      return this.delegate.getStatusText();
    }

    @Override
    public InputStream getBody() throws IOException {
      return this.delegate.getBody();
    }

    @Override
    public HttpHeaders getHeaders() {
      return this.delegate.getHeaders();
    }

    @Override
    public void close() {
      this.closed = true;
      this.delegate.close();
    }
  }

}
