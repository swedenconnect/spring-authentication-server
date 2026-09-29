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
package se.swedenconnect.spring.authnserver.oidc.client;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import org.springframework.util.StringUtils;

import com.nimbusds.langtag.LangTag;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.authentication.Requester;
import se.swedenconnect.spring.authnserver.registry.DisplayName;
import se.swedenconnect.spring.authnserver.registry.Logo;
import se.swedenconnect.spring.authnserver.registry.RequesterRecord;

/**
 * What a client registry backend knows about an OpenID Connect client: its {@code client_id}, its client metadata
 * and the trust mark types it holds.
 * <p>
 * Trust mark types of a record that comes from the configuration or from a client repository are set by the
 * operator, who vouches for them. They are not verified.
 * </p>
 *
 * @param clientId the {@code client_id} of the client
 * @param metadata the client metadata
 * @param trustMarkTypes the trust mark types that the client holds
 * @author Martin Lindström
 */
public record OidcClientRecord(
    @Nonnull String clientId, @Nonnull OIDCClientMetadata metadata, @Nonnull Set<String> trustMarkTypes) {

  /**
   * Constructor.
   *
   * @param clientId the {@code client_id} of the client
   * @param metadata the client metadata
   * @param trustMarkTypes the trust mark types that the client holds
   */
  public OidcClientRecord {
    Objects.requireNonNull(clientId, "clientId must not be null");
    Objects.requireNonNull(metadata, "metadata must not be null");
    if (!StringUtils.hasText(clientId)) {
      throw new IllegalArgumentException("clientId must not be empty");
    }
    trustMarkTypes = Set.copyOf(Objects.requireNonNull(trustMarkTypes, "trustMarkTypes must not be null"));
  }

  /**
   * Creates a record for a client that holds no trust marks.
   *
   * @param clientId the {@code client_id} of the client
   * @param metadata the client metadata
   * @return an {@link OidcClientRecord}
   */
  public static @Nonnull OidcClientRecord of(
      final @Nonnull String clientId, final @Nonnull OIDCClientMetadata metadata) {
    return new OidcClientRecord(clientId, metadata, Set.of());
  }

  /**
   * Creates the protocol-neutral record for the client. The display names come from {@code client_name} and the
   * logotypes from {@code logo_uri}, both in every language that the metadata gives them in, and the marks are the
   * trust mark types.
   *
   * @return a {@link RequesterRecord}
   */
  public @Nonnull RequesterRecord toRequesterRecord() {
    return new RequesterRecord(
        new Requester(AuthenticationProtocol.OIDC, this.clientId),
        displayNames(this.metadata),
        logos(this.metadata),
        this.trustMarkTypes,
        this.metadata);
  }

  /**
   * Gets the display names of the client, that is, the values of {@code client_name} and its language-tagged forms.
   *
   * @param metadata the client metadata
   * @return a list of display names
   */
  private static @Nonnull List<DisplayName> displayNames(final @Nonnull OIDCClientMetadata metadata) {
    final Map<LangTag, String> entries = metadata.getNameEntries();
    if (entries == null || entries.isEmpty()) {
      return List.of();
    }
    final List<DisplayName> names = new ArrayList<>(entries.size());
    entries.forEach((language, name) -> {
      if (StringUtils.hasText(name)) {
        names.add(new DisplayName(language(language), name));
      }
    });
    return List.copyOf(names);
  }

  /**
   * Gets the logotypes of the client, that is, the values of {@code logo_uri} and its language-tagged forms.
   *
   * @param metadata the client metadata
   * @return a list of logotypes
   */
  private static @Nonnull List<Logo> logos(final @Nonnull OIDCClientMetadata metadata) {
    final Map<LangTag, URI> entries = metadata.getLogoURIEntries();
    if (entries == null || entries.isEmpty()) {
      return List.of();
    }
    final List<Logo> logos = new ArrayList<>(entries.size());
    entries.forEach((language, uri) -> {
      if (uri != null) {
        logos.add(new Logo(language(language), uri.toString(), null, null));
      }
    });
    return List.copyOf(logos);
  }

  /**
   * Gets the language tag as a string.
   *
   * @param language the language tag, or {@code null} for a value given without one
   * @return the language tag as a string, or {@code null}
   */
  private static @Nullable String language(final @Nullable LangTag language) {
    return language != null ? language.toString() : null;
  }

}
