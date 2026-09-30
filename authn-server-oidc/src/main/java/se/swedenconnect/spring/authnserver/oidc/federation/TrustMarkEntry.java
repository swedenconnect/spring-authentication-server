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

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

import org.jspecify.annotations.NonNull;

/**
 * An element of the {@code trust_marks} claim of an entity configuration, OpenID Federation 1.0, Section 3.1.2.
 *
 * @param trustMarkType the trust mark type
 * @param trustMark the trust mark JWT
 * @author Martin Lindström
 */
public record TrustMarkEntry(@NonNull String trustMarkType, @NonNull String trustMark) {

  /**
   * Constructor.
   *
   * @param trustMarkType the trust mark type
   * @param trustMark the trust mark JWT
   */
  public TrustMarkEntry {
    Objects.requireNonNull(trustMarkType, "trustMarkType must not be null");
    Objects.requireNonNull(trustMark, "trustMark must not be null");
  }

  /**
   * Gets the element as a JSON object.
   *
   * @return a map holding {@code trust_mark_type} and {@code trust_mark}
   */
  public @NonNull Map<String, Object> toJson() {
    final Map<String, Object> json = new LinkedHashMap<>();
    json.put("trust_mark_type", this.trustMarkType);
    json.put("trust_mark", this.trustMark);
    return json;
  }

}
