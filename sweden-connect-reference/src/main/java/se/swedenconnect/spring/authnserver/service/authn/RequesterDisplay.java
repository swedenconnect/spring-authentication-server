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
package se.swedenconnect.spring.authnserver.service.authn;

import java.util.List;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import se.swedenconnect.spring.authnserver.registry.DisplayName;
import se.swedenconnect.spring.authnserver.registry.Logo;
import se.swedenconnect.spring.authnserver.registry.RequesterRecord;

/**
 * The name and logotype that the user picker shows for the requester, taken from the protocol-neutral part of its
 * record in the client registry: for a SAML Service Provider its metadata UI information, and for an OpenID Connect
 * client its {@code client_name} and {@code logo_uri}.
 *
 * @param displayName the name of the requester, or {@code null}
 * @param logoUrl the URL of the logotype of the requester, or {@code null}
 * @author Martin Lindström
 */
public record RequesterDisplay(@Nullable String displayName, @Nullable String logoUrl) {

  /** A logotype lower than this is small. */
  private static final int SMALL_LOGO_HEIGHT = 40;

  /** A logotype higher than this is large. */
  private static final int LARGE_LOGO_HEIGHT = 100;

  /**
   * Gets what to show for a requester in a given language.
   * <p>
   * The name for the language is used, and otherwise the first name the requester has. The logotypes for the language,
   * together with those that are not tied to a language, are chosen among, and if there are none of those, all
   * logotypes of the requester. The first logotype that is wider than it is high, or higher than 40 and lower than 100
   * pixels, is used. Otherwise the smallest one higher than 100 pixels is used, then the largest one lower than 40
   * pixels, and if the size of no logotype is known, the first one.
   * </p>
   *
   * @param record the record of the requester
   * @param language the language of the page
   * @return the name and logotype to show
   */
  public static @NonNull RequesterDisplay of(final @NonNull RequesterRecord record, final @NonNull String language) {
    Objects.requireNonNull(record, "record must not be null");
    String name = record.getDisplayName(language);
    if (name == null && !record.displayNames().isEmpty()) {
      name = record.displayNames().getFirst().name();
    }
    return new RequesterDisplay(name, selectLogo(logosForLanguage(record.logos(), language)));
  }

  /**
   * Gets the logotypes for the language, and those that are not tied to a language. If there are none, all logotypes
   * are returned.
   *
   * @param logos the logotypes of the requester
   * @param language the language
   * @return the logotypes to choose among
   */
  private static @NonNull List<Logo> logosForLanguage(final @NonNull List<Logo> logos, final @NonNull String language) {
    final String primary = DisplayName.primaryLanguage(language);
    final List<Logo> candidates = logos.stream()
        .filter(l -> l.language() == null || language.equalsIgnoreCase(l.language())
            || Objects.equals(primary, l.getPrimaryLanguage()))
        .toList();
    return candidates.isEmpty() ? logos : candidates;
  }

  /**
   * Selects the logotype to show, using the rules of the old reference IdP.
   *
   * @param logos the logotypes to choose among
   * @return the URL of the selected logotype, or {@code null} if there are none
   */
  private static @Nullable String selectLogo(final @NonNull List<Logo> logos) {
    Logo small = null;
    Logo large = null;
    for (final Logo logo : logos) {
      final Integer height = logo.height();
      if (height == null) {
        continue;
      }
      if (logo.width() != null && logo.width() > height) {
        return logo.url();
      }
      if (height > SMALL_LOGO_HEIGHT && height < LARGE_LOGO_HEIGHT) {
        return logo.url();
      }
      if (height < SMALL_LOGO_HEIGHT) {
        if (small == null || height > small.height()) {
          small = logo;
        }
      }
      else if (height > LARGE_LOGO_HEIGHT && (large == null || height < large.height())) {
        large = logo;
      }
    }
    if (large != null) {
      return large.url();
    }
    if (small != null) {
      return small.url();
    }
    return logos.isEmpty() ? null : logos.getFirst().url();
  }

}
