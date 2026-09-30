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
package se.swedenconnect.spring.authnserver.saml.config;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * The elements of the IdP metadata that are given as values to the {@link Saml2IdpMetadataEndpointConfigurer}. The
 * UI information, the organization and the contact persons are given as the protocol-neutral
 * {@link se.swedenconnect.spring.authnserver.entity.EntityInformation} types.
 *
 * @author Martin Lindström
 */
public final class IdpMetadataElements {

  /**
   * An {@code alg:SigningMethod} element.
   *
   * @param algorithm the algorithm URI
   * @param minKeySize the smallest key size in bits, or {@code null}
   * @param maxKeySize the largest key size in bits, or {@code null}
   */
  public record SigningMethod(@NonNull String algorithm, @Nullable Integer minKeySize, @Nullable Integer maxKeySize) {
  }

  /**
   * An {@code md:EncryptionMethod} element, placed under the {@code md:KeyDescriptor} of the encryption key.
   *
   * @param algorithm the algorithm URI
   * @param keySize the key size, or {@code null}
   * @param oaepParams the OAEP parameters in Base64, or {@code null}
   * @param digestMethod the digest algorithm URI for key transport algorithms that need one, or {@code null}
   */
  public record EncryptionMethod(@NonNull String algorithm, @Nullable Integer keySize, @Nullable String oaepParams,
      @Nullable String digestMethod) {
  }

  // Hidden constructor
  private IdpMetadataElements() {
  }

}
