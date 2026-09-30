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
package se.swedenconnect.spring.authnserver.oidc.attributes.mapping;

import java.util.Collection;

import org.jspecify.annotations.NonNull;

import se.swedenconnect.spring.authnserver.attributes.mapping.ToProtocolAttributeMapper;
import se.swedenconnect.spring.authnserver.oidc.attributes.UserClaim;

/**
 * A mapper from generic attributes into claims that tells which claims it may produce. The OpenID Provider uses this
 * to work out the claims that it supports from the attributes of the authentication providers. A mapper that does not
 * implement this interface still maps attributes, but its claims are not declared as supported unless they are
 * configured.
 *
 * @author Martin Lindström
 */
public interface ToClaimMapper extends ToProtocolAttributeMapper<UserClaim> {

  /**
   * Gets the claims that the mapper may produce from an attribute.
   *
   * @param identifier the attribute identifier, one of {@link #getSupportedIdentifiers()}
   * @return the claim names, empty if the identifier is not handled
   */
  @NonNull Collection<String> getClaimNames(final @NonNull String identifier);

}
