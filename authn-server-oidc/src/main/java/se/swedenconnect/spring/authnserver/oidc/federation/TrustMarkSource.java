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
package se.swedenconnect.spring.authnserver.oidc.federation;

import java.net.URI;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.util.StringUtils;

import com.nimbusds.jose.jwk.JWKSet;

/**
 * Where the OpenID Provider gets one of its own trust marks: the trust mark type, and the issuer with its keys and,
 * optionally, its trust mark endpoint.
 *
 * @param trustMarkType the trust mark type
 * @param issuer the entity identifier of the trust mark issuer
 * @param endpoint the trust mark endpoint of the issuer, or {@code null} to use the
 *     {@code federation_trust_mark_endpoint} that the issuer publishes in its entity configuration
 * @param issuerKeys the federation keys of the issuer, that the trust mark is verified with
 * @author Martin Lindström
 */
public record TrustMarkSource(
    @NonNull String trustMarkType,
    @NonNull String issuer,
    @Nullable URI endpoint,
    @NonNull JWKSet issuerKeys) {

  /**
   * Constructor.
   *
   * @param trustMarkType the trust mark type
   * @param issuer the entity identifier of the trust mark issuer
   * @param endpoint the trust mark endpoint of the issuer, or {@code null}
   * @param issuerKeys the federation keys of the issuer
   */
  public TrustMarkSource {
    if (!StringUtils.hasText(trustMarkType)) {
      throw new IllegalArgumentException("trustMarkType must be set and not empty");
    }
    if (!StringUtils.hasText(issuer)) {
      throw new IllegalArgumentException("issuer must be set and not empty");
    }
    Objects.requireNonNull(issuerKeys, "issuerKeys must not be null");
    if (issuerKeys.getKeys().isEmpty()) {
      throw new IllegalArgumentException("No keys are given for the trust mark issuer " + issuer);
    }
  }

}
