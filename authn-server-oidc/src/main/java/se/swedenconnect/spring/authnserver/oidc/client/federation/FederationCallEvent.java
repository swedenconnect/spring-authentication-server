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

import java.io.Serial;
import java.time.Instant;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.context.ApplicationEvent;

import se.swedenconnect.spring.authnserver.LibraryVersion;

/**
 * Published by the {@link HttpFederationClient} for every call it makes to a federation service, telling how the call
 * went. It is what the health of the federation services is built from, see {@link FederationServiceMonitor}.
 *
 * @author Martin Lindström
 */
public class FederationCallEvent extends ApplicationEvent {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /** The call that was made. */
  private final Call call;

  /** The endpoint that was called. */
  private final String endpoint;

  /**
   * The entity identifier of the trust mark issuer, or of the entity whose entity configuration is fetched, or
   * {@code null} for a resolve call.
   */
  private final String issuer;

  /** How the call went. */
  private final Outcome outcome;

  /** What went wrong, or {@code null} if the call succeeded. */
  private final String error;

  /**
   * Constructor.
   *
   * @param call the call that was made
   * @param endpoint the endpoint that was called
   * @param issuer the entity identifier of the trust mark issuer, or of the entity whose entity configuration is
   *     fetched, or {@code null} for a resolve call
   * @param outcome how the call went
   * @param error what went wrong, or {@code null} if the call succeeded
   */
  public FederationCallEvent(final @NonNull Call call, final @NonNull String endpoint, final @Nullable String issuer,
      final @NonNull Outcome outcome, final @Nullable String error) {
    super(Objects.requireNonNull(endpoint, "endpoint must not be null"));
    this.call = Objects.requireNonNull(call, "call must not be null");
    this.endpoint = endpoint;
    this.issuer = issuer;
    this.outcome = Objects.requireNonNull(outcome, "outcome must not be null");
    this.error = error;
  }

  /**
   * Gets the call that was made.
   *
   * @return the call
   */
  public @NonNull Call getCall() {
    return this.call;
  }

  /**
   * Gets the endpoint that was called.
   *
   * @return the endpoint
   */
  public @NonNull String getEndpoint() {
    return this.endpoint;
  }

  /**
   * Gets the entity identifier of the trust mark issuer, or of the entity whose entity configuration is fetched.
   *
   * @return the entity identifier, or {@code null} for a resolve call
   */
  public @Nullable String getIssuer() {
    return this.issuer;
  }

  /**
   * Gets how the call went.
   *
   * @return the outcome
   */
  public @NonNull Outcome getOutcome() {
    return this.outcome;
  }

  /**
   * Gets what went wrong.
   *
   * @return the error, or {@code null} if the call succeeded
   */
  public @Nullable String getError() {
    return this.error;
  }

  /**
   * Gets when the call was made.
   *
   * @return the time
   */
  public @NonNull Instant getTime() {
    return Instant.ofEpochMilli(this.getTimestamp());
  }

  /**
   * Gets the kind of service that was called.
   *
   * @return the kind of service
   */
  public @NonNull ServiceType getServiceType() {
    return switch (this.call) {
      case RESOLVE -> ServiceType.RESOLVER;
      case ENTITY_CONFIGURATION -> ServiceType.ENTITY_CONFIGURATION;
      case TRUST_MARK, TRUST_MARK_STATUS -> ServiceType.TRUST_MARK_ISSUER;
    };
  }

  /**
   * Gets the identity of the service that was called: the endpoint of a resolver, the entity identifier of a trust
   * mark issuer, so that the trust mark endpoint and the status endpoint of an issuer count as one service, and the
   * entity identifier of an entity whose entity configuration is fetched.
   *
   * @return the identity of the service
   */
  public @NonNull String getServiceId() {
    return this.getServiceType() != ServiceType.RESOLVER && this.issuer != null ? this.issuer : this.endpoint;
  }

  /**
   * A call that is made to a federation service.
   */
  public enum Call {

    /** A resolve request, OpenID Federation 1.0, Section 8.3. */
    RESOLVE,

    /** A trust mark request, OpenID Federation 1.0, Section 8.6. */
    TRUST_MARK,

    /** A trust mark status request, OpenID Federation 1.0, Section 8.4. */
    TRUST_MARK_STATUS,

    /**
     * A request for the entity configuration of an entity, OpenID Federation 1.0, Section 9, made to find an endpoint
     * that the entity publishes.
     */
    ENTITY_CONFIGURATION

  }

  /**
   * A kind of federation service.
   */
  public enum ServiceType {

    /** A resolver. */
    RESOLVER,

    /** A trust mark issuer. */
    TRUST_MARK_ISSUER,

    /** An entity whose entity configuration is fetched to find its endpoints. */
    ENTITY_CONFIGURATION

  }

  /**
   * How a call went.
   */
  public enum Outcome {

    /** The service answered. An answer that it does not know the subject is a success. */
    SUCCESS,

    /** The service answered with an error, or with something that is not a valid response. */
    ERROR_RESPONSE,

    /** The service could not be reached. */
    UNREACHABLE

  }

}
