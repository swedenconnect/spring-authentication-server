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
package se.swedenconnect.spring.authnserver.oidc.authnrequest;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;

import java.io.Serial;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.springframework.security.authentication.AbstractAuthenticationToken;

import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import se.swedenconnect.spring.authnserver.LibraryVersion;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.authentication.Requester;
import se.swedenconnect.spring.authnserver.oidc.response.OidcResponseTarget;
import se.swedenconnect.spring.authnserver.registry.RequesterRecord;

/**
 * An OpenID Connect authentication request while it is being processed: the client that sent it, its parameters
 * with those of a request object merged in, and where to answer.
 *
 * @author Martin Lindström
 */
public class OidcAuthnRequestAuthenticationToken extends AbstractAuthenticationToken {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /** The record of the client in the client registry. */
  private final transient RequesterRecord requesterRecord;

  /** The client metadata. */
  private final transient OIDCClientMetadata clientMetadata;

  /** The parameters of the request, with those of a request object merged in. */
  private final Map<String, List<String>> parameters;

  /** The decoded request object, or {@code null}. */
  private final transient RequestObjectDecoder.DecodedJwt requestObject;

  /** Where and how to answer. */
  private final OidcResponseTarget responseTarget;

  /**
   * Constructor.
   *
   * @param requesterRecord the record of the client
   * @param parameters the parameters, with those of a request object merged in
   * @param requestObject the decoded request object, or {@code null} if the request had none
   * @param responseTarget where and how to answer
   */
  public OidcAuthnRequestAuthenticationToken(final @Nonnull RequesterRecord requesterRecord,
      final @Nonnull Map<String, List<String>> parameters,
      final @Nullable RequestObjectDecoder.DecodedJwt requestObject,
      final @Nonnull OidcResponseTarget responseTarget) {
    super(List.of());
    this.requesterRecord = Objects.requireNonNull(requesterRecord, "requesterRecord must not be null");
    this.clientMetadata = requesterRecord.getProtocolMetadata(OIDCClientMetadata.class);
    this.parameters = Map.copyOf(Objects.requireNonNull(parameters, "parameters must not be null"));
    this.requestObject = requestObject;
    this.responseTarget = Objects.requireNonNull(responseTarget, "responseTarget must not be null");
    this.setAuthenticated(false);
  }

  /** {@inheritDoc} */
  @Override
  public @Nonnull Object getCredentials() {
    return "";
  }

  /**
   * Gets the {@code client_id} of the client.
   */
  @Override
  public @Nonnull Object getPrincipal() {
    return this.getClientId();
  }

  /**
   * Gets the {@code client_id} of the client.
   *
   * @return the {@code client_id}
   */
  public @Nonnull String getClientId() {
    return this.responseTarget.clientId();
  }

  /**
   * Gets the record of the client in the client registry.
   *
   * @return the requester record
   */
  public @Nonnull RequesterRecord getRequesterRecord() {
    return this.requesterRecord;
  }

  /**
   * Gets the client metadata.
   *
   * @return the client metadata
   */
  public @Nonnull OIDCClientMetadata getClientMetadata() {
    return this.clientMetadata;
  }

  /**
   * Gets the parameters of the request, with those of a request object merged in. A parameter of the request object
   * replaces a parameter of the same name, as OpenID Connect Core, Section 6.3.3, states.
   *
   * @return the parameters
   */
  public @Nonnull Map<String, List<String>> getParameters() {
    return this.parameters;
  }

  /**
   * Gets the decoded request object.
   *
   * @return the request object, or {@code null} if the request had none
   */
  public @Nullable RequestObjectDecoder.DecodedJwt getRequestObject() {
    return this.requestObject;
  }

  /**
   * Gets where and how to answer.
   *
   * @return the response target
   */
  public @Nonnull OidcResponseTarget getResponseTarget() {
    return this.responseTarget;
  }

  /**
   * Gets a string that identifies the request, for logging.
   *
   * @return a log string
   */
  public @Nonnull String getLogString() {
    return logString(this.getClientId());
  }

  /**
   * Gets the log string of a request from a client.
   *
   * @param clientId the {@code client_id}
   * @return a log string
   */
  static @Nonnull String logString(final @Nonnull String clientId) {
    return "requester: '%s'".formatted(new Requester(AuthenticationProtocol.OIDC, clientId));
  }

}
