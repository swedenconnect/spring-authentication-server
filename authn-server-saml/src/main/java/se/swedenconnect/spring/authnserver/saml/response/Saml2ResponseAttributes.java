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
package se.swedenconnect.spring.authnserver.saml.response;

import jakarta.servlet.http.HttpServletRequest;

import java.io.Serial;
import java.io.Serializable;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;

import se.swedenconnect.opensaml.common.utils.SerializableOpenSamlObject;
import se.swedenconnect.spring.authnserver.LibraryVersion;

/**
 * What the Identity Provider needs to send a response to the Service Provider: where to send it, which request it
 * answers, the relay state, and the Service Provider metadata.
 * <p>
 * The attributes are established during the processing of the authentication request, once the assertion consumer
 * service is known. From then on, a failure is answered with an error response. They are kept as an attribute of the
 * HTTP request, see {@link #setOnRequest(HttpServletRequest, Saml2ResponseAttributes)}.
 * </p>
 *
 * @param destination the URL of the assertion consumer service
 * @param inResponseTo the ID of the authentication request
 * @param relayState the relay state, or {@code null}
 * @param peerMetadata the metadata of the Service Provider
 * @author Martin Lindström
 */
public record Saml2ResponseAttributes(@NonNull String destination, @NonNull String inResponseTo,
    @Nullable String relayState, @NonNull SerializableOpenSamlObject<EntityDescriptor> peerMetadata)
    implements Serializable {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /** The name of the request attribute holding the response attributes. */
  public static final String REQUEST_ATTRIBUTE = Saml2ResponseAttributes.class.getName();

  /**
   * Constructor.
   *
   * @param destination the URL of the assertion consumer service
   * @param inResponseTo the ID of the authentication request
   * @param relayState the relay state, or {@code null}
   * @param peerMetadata the metadata of the Service Provider
   */
  public Saml2ResponseAttributes {
    Objects.requireNonNull(destination, "destination must not be null");
    Objects.requireNonNull(inResponseTo, "inResponseTo must not be null");
    Objects.requireNonNull(peerMetadata, "peerMetadata must not be null");
  }

  /**
   * Constructor.
   *
   * @param destination the URL of the assertion consumer service
   * @param inResponseTo the ID of the authentication request
   * @param relayState the relay state, or {@code null}
   * @param peerMetadata the metadata of the Service Provider
   */
  public Saml2ResponseAttributes(final @NonNull String destination, final @NonNull String inResponseTo,
      final @Nullable String relayState, final @NonNull EntityDescriptor peerMetadata) {
    this(destination, inResponseTo, relayState, new SerializableOpenSamlObject<>(peerMetadata));
  }

  /**
   * Gets the metadata of the Service Provider.
   *
   * @return the metadata
   */
  public @NonNull EntityDescriptor getPeerMetadata() {
    return this.peerMetadata.get();
  }

  /**
   * Gets the entityID of the Service Provider.
   *
   * @return the entityID
   */
  public @NonNull String getEntityId() {
    return this.getPeerMetadata().getEntityID();
  }

  /**
   * Keeps the response attributes as an attribute of the HTTP request.
   *
   * @param request the HTTP request
   * @param attributes the response attributes
   */
  public static void setOnRequest(final @NonNull HttpServletRequest request,
      final @NonNull Saml2ResponseAttributes attributes) {
    request.setAttribute(REQUEST_ATTRIBUTE, attributes);
  }

  /**
   * Gets the response attributes that are kept as an attribute of the HTTP request.
   *
   * @param request the HTTP request
   * @return the response attributes, or {@code null} if none have been established
   */
  public static @Nullable Saml2ResponseAttributes fromRequest(final @NonNull HttpServletRequest request) {
    return request.getAttribute(REQUEST_ATTRIBUTE) instanceof final Saml2ResponseAttributes attributes
        ? attributes
        : null;
  }

}
