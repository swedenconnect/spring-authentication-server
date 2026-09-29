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
package se.swedenconnect.spring.authnserver.saml.authentication;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;

import java.io.Serial;
import java.io.Serializable;
import java.util.Objects;

import se.swedenconnect.opensaml.sweid.saml2.signservice.sap.SADRequest;
import se.swedenconnect.spring.authnserver.LibraryVersion;

/**
 * A representation of the SAML {@code SADRequest} extension, see
 * <a href="https://docs.swedenconnect.se/technical-framework/updates/13_-_Signature_Activation_Protocol.html">Signature
 * Activation Protocol for Federated Signing</a>.
 * <p>
 * The extension is only sent by signature services, so it is part of the SAML authentication requirements and has no
 * protocol-neutral counterpart.
 * </p>
 *
 * @author Martin Lindström
 */
public class SadRequestExtension implements Serializable {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /** The ID of the SADRequest. */
  private final String id;

  /** The entityID of the service that requested the signature. */
  private final String requesterId;

  /** The ID of the corresponding SignRequest. */
  private final String signRequestId;

  /** The number of documents to sign. */
  private final Integer documentCount;

  /**
   * Constructor.
   *
   * @param id the ID of the SADRequest
   * @param requesterId the entityID of the service that requested the signature
   * @param signRequestId the ID of the corresponding SignRequest
   * @param documentCount the number of documents to sign
   */
  public SadRequestExtension(final @Nullable String id, final @Nullable String requesterId,
      final @Nullable String signRequestId, final @Nullable Integer documentCount) {
    this.id = id;
    this.requesterId = requesterId;
    this.signRequestId = signRequestId;
    this.documentCount = documentCount;
  }

  /**
   * Constructor taking the OpenSAML representation. The extension is not validated.
   *
   * @param sadRequest the {@code SADRequest} extension
   */
  public SadRequestExtension(final @Nonnull SADRequest sadRequest) {
    Objects.requireNonNull(sadRequest, "sadRequest must not be null");
    this.id = sadRequest.getID();
    this.requesterId = sadRequest.getRequesterID();
    this.signRequestId = sadRequest.getSignRequestID();
    this.documentCount = sadRequest.getDocCount();
  }

  /**
   * Gets the ID of the SADRequest.
   *
   * @return the ID, or {@code null} if it is not set
   */
  public @Nullable String getId() {
    return this.id;
  }

  /**
   * Gets the entityID of the service that requested the signature.
   *
   * @return the requester ID, or {@code null} if it is not set
   */
  public @Nullable String getRequesterId() {
    return this.requesterId;
  }

  /**
   * Gets the ID of the corresponding SignRequest.
   *
   * @return the SignRequest ID, or {@code null} if it is not set
   */
  public @Nullable String getSignRequestId() {
    return this.signRequestId;
  }

  /**
   * Gets the number of documents to sign.
   *
   * @return the document count, or {@code null} if it is not set
   */
  public @Nullable Integer getDocumentCount() {
    return this.documentCount;
  }

  /** {@inheritDoc} */
  @Override
  public boolean equals(final Object obj) {
    if (this == obj) {
      return true;
    }
    if (!(obj instanceof final SadRequestExtension other)) {
      return false;
    }
    return Objects.equals(this.id, other.id)
        && Objects.equals(this.requesterId, other.requesterId)
        && Objects.equals(this.signRequestId, other.signRequestId)
        && Objects.equals(this.documentCount, other.documentCount);
  }

  /** {@inheritDoc} */
  @Override
  public int hashCode() {
    return Objects.hash(this.id, this.requesterId, this.signRequestId, this.documentCount);
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return "id=%s, requester-id=%s, sign-request-id=%s, document-count=%s".formatted(this.id, this.requesterId,
        this.signRequestId, this.documentCount);
  }

}
