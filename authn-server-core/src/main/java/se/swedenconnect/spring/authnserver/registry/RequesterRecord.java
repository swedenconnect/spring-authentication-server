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
package se.swedenconnect.spring.authnserver.registry;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.authentication.Requester;

/**
 * What the {@link ClientRegistry} knows about a requester: a protocol-neutral part that any part of the server may
 * use, and the metadata of the protocol that the requester speaks.
 * <p>
 * The protocol metadata is an {@code EntityDescriptor} for a SAML Service Provider and an {@code OIDCClientMetadata}
 * object for an OpenID Connect client. Only the protocol modules look at it; use
 * {@link #getProtocolMetadata(Class)} to get it in its own type.
 * </p>
 *
 * @param requester the requester that the record describes
 * @param displayNames the names that the requester may be presented by, one per language. A name without a language
 *          may appear, at most one
 * @param logos the logotypes that the requester may be presented by
 * @param marks the marks that the requester holds, see {@link ClientRegistry}
 * @param protocolMetadata the metadata of the requester, in the form of the protocol it speaks
 * @author Martin Lindström
 */
public record RequesterRecord(
    @Nonnull Requester requester,
    @Nonnull List<DisplayName> displayNames,
    @Nonnull List<Logo> logos,
    @Nonnull Set<String> marks,
    @Nonnull Object protocolMetadata) {

  /**
   * Constructor.
   *
   * @param requester the requester that the record describes
   * @param displayNames the names that the requester may be presented by
   * @param logos the logotypes that the requester may be presented by
   * @param marks the marks that the requester holds
   * @param protocolMetadata the metadata of the requester, in the form of the protocol it speaks
   */
  public RequesterRecord {
    Objects.requireNonNull(requester, "requester must not be null");
    Objects.requireNonNull(protocolMetadata, "protocolMetadata must not be null");
    displayNames = List.copyOf(Objects.requireNonNull(displayNames, "displayNames must not be null"));
    logos = List.copyOf(Objects.requireNonNull(logos, "logos must not be null"));
    marks = Set.copyOf(Objects.requireNonNull(marks, "marks must not be null"));
  }

  /**
   * Gets the protocol that the requester speaks.
   *
   * @return the protocol
   */
  public @Nonnull AuthenticationProtocol getProtocol() {
    return this.requester.protocol();
  }

  /**
   * Gets the identity of the requester, a SAML SP entityID or an OpenID Connect {@code client_id}.
   *
   * @return the requester identity
   */
  public @Nonnull String getIdentifier() {
    return this.requester.identifier();
  }

  /**
   * Gets the protocol metadata in its own type.
   *
   * @param type the type of the protocol metadata
   * @param <T> the type of the protocol metadata
   * @return the protocol metadata
   * @throws IllegalArgumentException if the metadata is not of the requested type
   */
  public <T> @Nonnull T getProtocolMetadata(final @Nonnull Class<T> type) {
    Objects.requireNonNull(type, "type must not be null");
    if (!type.isInstance(this.protocolMetadata)) {
      throw new IllegalArgumentException("The protocol metadata of %s is not a %s".formatted(
          this.requester, type.getName()));
    }
    return type.cast(this.protocolMetadata);
  }

  /**
   * Gets the name to present the requester by in the given language.
   * <p>
   * The name for the exact language tag is used if there is one, otherwise the name for a language with the same
   * primary subtag, and otherwise the name that is not tied to a language.
   * </p>
   *
   * @param language the language tag, or {@code null} to ask only for a name without a language
   * @return a display name, or {@code null} if the requester has none that can be used
   */
  public @Nullable String getDisplayName(final @Nullable String language) {
    if (language != null) {
      final Optional<DisplayName> exact = this.displayNames.stream()
          .filter(d -> language.equals(d.language()))
          .findFirst();
      if (exact.isPresent()) {
        return exact.get().name();
      }
      final String primary = DisplayName.primaryLanguage(language);
      final Optional<DisplayName> sameLanguage = this.displayNames.stream()
          .filter(d -> Objects.equals(primary, d.getPrimaryLanguage()))
          .findFirst();
      if (sameLanguage.isPresent()) {
        return sameLanguage.get().name();
      }
    }
    return this.displayNames.stream()
        .filter(d -> d.language() == null)
        .map(DisplayName::name)
        .findFirst()
        .orElse(null);
  }

  /**
   * Tells whether the requester holds the given mark.
   *
   * @param mark the mark identifier
   * @return {@code true} if the requester holds the mark and {@code false} otherwise
   */
  public boolean hasMark(final @Nonnull String mark) {
    return this.marks.contains(Objects.requireNonNull(mark, "mark must not be null"));
  }

  /**
   * Creates a copy of the record where the given marks have been added.
   *
   * @param additionalMarks the marks to add
   * @return a {@link RequesterRecord}
   */
  public @Nonnull RequesterRecord withMarks(final @Nonnull Collection<String> additionalMarks) {
    Objects.requireNonNull(additionalMarks, "additionalMarks must not be null");
    if (this.marks.containsAll(additionalMarks)) {
      return this;
    }
    final Set<String> all = new LinkedHashSet<>(this.marks);
    all.addAll(additionalMarks);
    return new RequesterRecord(this.requester, this.displayNames, this.logos, all, this.protocolMetadata);
  }

  /**
   * Gets the logotype to present the requester by in the given language.
   * <p>
   * A logotype for the exact language tag is used if there is one, otherwise a logotype for a language with the same
   * primary subtag, otherwise a logotype that is not tied to a language, and otherwise the first one.
   * </p>
   *
   * @param language the language tag, or {@code null} to ask only for a logotype without a language
   * @return a {@link Logo}, or {@code null} if the requester has none
   */
  public @Nullable Logo getLogo(final @Nullable String language) {
    if (language != null) {
      final List<Logo> candidates = new ArrayList<>();
      this.logos.stream().filter(l -> language.equals(l.language())).forEach(candidates::add);
      if (candidates.isEmpty()) {
        final String primary = DisplayName.primaryLanguage(language);
        this.logos.stream()
            .filter(l -> l.language() != null)
            .filter(l -> Objects.equals(primary, l.getPrimaryLanguage()))
            .forEach(candidates::add);
      }
      if (!candidates.isEmpty()) {
        return candidates.get(0);
      }
    }
    return this.logos.stream()
        .filter(l -> l.language() == null)
        .findFirst()
        .orElseGet(() -> this.logos.isEmpty() ? null : this.logos.get(0));
  }

}
