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

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatusCode;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestClient;

import com.nimbusds.jwt.SignedJWT;

import se.swedenconnect.oidf.common.entity.entity.integration.federation.EntityConfigurationRequest;
import se.swedenconnect.oidf.common.entity.entity.integration.federation.FederationClient;
import se.swedenconnect.oidf.common.entity.entity.integration.federation.FederationRequest;
import se.swedenconnect.oidf.common.entity.entity.integration.federation.FederationTrustMarkStatusRequest;
import se.swedenconnect.oidf.common.entity.entity.integration.federation.FetchRequest;
import se.swedenconnect.oidf.common.entity.entity.integration.federation.ResolveRequest;
import se.swedenconnect.oidf.common.entity.entity.integration.federation.SubordinateListingRequest;
import se.swedenconnect.oidf.common.entity.entity.integration.federation.TrustMarkListingRequest;
import se.swedenconnect.oidf.common.entity.entity.integration.federation.TrustMarkRequest;
import se.swedenconnect.oidf.common.entity.entity.integration.trustmark.TrustMarkStatusResponse;
import se.swedenconnect.spring.authnserver.registry.ClientRegistryException;

/**
 * A {@link FederationClient} that makes the two federation calls that the client registry needs over HTTP: the
 * resolve request of
 * <a href="https://openid.net/specs/openid-federation-1_0.html#section-8.3">OpenID Federation 1.0, Section 8.3</a>
 * and the trust mark request of Section 8.6.
 * <p>
 * The endpoint of a call is taken from the federation entity metadata of the request, under
 * {@value #FEDERATION_RESOLVE_ENDPOINT} and {@value #FEDERATION_TRUST_MARK_ENDPOINT}.
 * </p>
 * <p>
 * The other calls of the interface are not made by the client registry and are not implemented.
 * </p>
 *
 * @author Martin Lindström
 */
public class HttpFederationClient implements FederationClient {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(HttpFederationClient.class);

  /** The federation entity metadata parameter holding the resolve endpoint. */
  public static final String FEDERATION_RESOLVE_ENDPOINT = "federation_resolve_endpoint";

  /** The federation entity metadata parameter holding the trust mark endpoint. */
  public static final String FEDERATION_TRUST_MARK_ENDPOINT = "federation_trust_mark_endpoint";

  /** The HTTP client. */
  private final RestClient restClient;

  /**
   * Default constructor using a {@link RestClient} with the default settings.
   */
  public HttpFederationClient() {
    this(RestClient.create());
  }

  /**
   * Constructor.
   *
   * @param restClient the HTTP client to use
   */
  public HttpFederationClient(final @NonNull RestClient restClient) {
    this.restClient = Objects.requireNonNull(restClient, "restClient must not be null");
  }

  /** {@inheritDoc} */
  @Override
  public @Nullable SignedJWT resolve(final @NonNull FederationRequest<ResolveRequest> request) {
    final ResolveRequest parameters = request.parameters();
    final StringBuilder query = new StringBuilder();
    appendParameter(query, "sub", parameters.subject());
    appendParameter(query, "trust_anchor", parameters.trustAnchor());
    if (StringUtils.hasText(parameters.type())) {
      appendParameter(query, "entity_type", parameters.type());
    }
    return this.get(endpoint(request, FEDERATION_RESOLVE_ENDPOINT), query.toString(), "resolve");
  }

  /** {@inheritDoc} */
  @Override
  public @Nullable SignedJWT trustMark(final @NonNull FederationRequest<TrustMarkRequest> request) {
    final TrustMarkRequest parameters = request.parameters();
    final StringBuilder query = new StringBuilder();
    appendParameter(query, "trust_mark_type", parameters.trustMarkType().getValue());
    appendParameter(query, "sub", parameters.subject().getValue());
    return this.get(endpoint(request, FEDERATION_TRUST_MARK_ENDPOINT), query.toString(), "trust mark");
  }

  /**
   * Makes the call and parses the response as a signed JWT.
   *
   * @param endpoint the endpoint to call
   * @param query the query string, without the leading question mark
   * @param what what is asked for, used in error messages
   * @return a {@link SignedJWT}, or {@code null} if the endpoint answered that it has nothing
   * @throws ClientRegistryException if the call fails
   */
  private @Nullable SignedJWT get(final @NonNull String endpoint, final @NonNull String query,
      final @NonNull String what) throws ClientRegistryException {

    final URI uri = URI.create("%s%c%s".formatted(endpoint, endpoint.indexOf('?') >= 0 ? '&' : '?', query));
    log.trace("Making {} request to {}", what, uri);
    try {
      return this.restClient.get()
          .uri(uri)
          .exchange((clientRequest, clientResponse) -> {
            final HttpStatusCode status = clientResponse.getStatusCode();
            if (status.value() == 404) {
              log.debug("The {} endpoint {} answered 404", what, endpoint);
              return null;
            }
            if (!status.is2xxSuccessful()) {
              throw new ClientRegistryException(
                  "The %s endpoint %s answered %s".formatted(what, endpoint, status));
            }
            final String body = new String(clientResponse.getBody().readAllBytes(), StandardCharsets.UTF_8).trim();
            if (body.isEmpty()) {
              throw new ClientRegistryException(
                  "The %s endpoint %s answered with an empty body".formatted(what, endpoint));
            }
            try {
              return SignedJWT.parse(body);
            }
            catch (final ParseException e) {
              throw new ClientRegistryException(
                  "The %s endpoint %s did not answer with a signed JWT".formatted(what, endpoint), e);
            }
          }, false);
    }
    catch (final ClientRegistryException e) {
      throw e;
    }
    catch (final RuntimeException e) {
      throw new ClientRegistryException(
          "Failed to make %s request to %s - %s".formatted(what, endpoint, e.getMessage()), e);
    }
  }

  /**
   * Gets the endpoint of a call from the federation entity metadata of the request.
   *
   * @param request the request
   * @param parameter the metadata parameter holding the endpoint
   * @return the endpoint
   * @throws ClientRegistryException if the request does not give the endpoint
   */
  private static @NonNull String endpoint(
      final @NonNull FederationRequest<?> request, final @NonNull String parameter) {
    final Map<String, Object> metadata = request.federationEntityMetadata();
    final Object endpoint = metadata != null ? metadata.get(parameter) : null;
    if (endpoint instanceof final String value && StringUtils.hasText(value)) {
      return value;
    }
    throw new ClientRegistryException("No %s given for the federation request".formatted(parameter));
  }

  /**
   * Appends a query parameter, encoded according to {@code application/x-www-form-urlencoded}.
   *
   * @param query the query string being built
   * @param name the parameter name
   * @param value the parameter value
   */
  private static void appendParameter(
      final @NonNull StringBuilder query, final @NonNull String name, final @NonNull String value) {
    if (!query.isEmpty()) {
      query.append('&');
    }
    query.append(name).append('=').append(URLEncoder.encode(value, StandardCharsets.UTF_8));
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull SignedJWT entityConfiguration(final FederationRequest<EntityConfigurationRequest> request) {
    throw new UnsupportedOperationException("The entity configuration call is not implemented");
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull SignedJWT fetch(final FederationRequest<FetchRequest> request) {
    throw new UnsupportedOperationException("The fetch call is not implemented");
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull List<String> subordinateListing(final FederationRequest<SubordinateListingRequest> request) {
    throw new UnsupportedOperationException("The subordinate listing call is not implemented");
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull List<String> trustMarkedListing(final FederationRequest<TrustMarkListingRequest> request) {
    throw new UnsupportedOperationException("The trust marked listing call is not implemented");
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull TrustMarkStatusResponse trustMarkStatus(
      final FederationRequest<FederationTrustMarkStatusRequest> request) {
    throw new UnsupportedOperationException("The trust mark status call is not implemented");
  }

}
