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
package se.swedenconnect.spring.authnserver.oidc.client.federation;

import java.io.IOException;
import java.net.URI;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

/**
 * Checks the registration of a federation client with {@code subject_type} set to {@code pairwise}, so that its
 * pairwise {@code sub} values cannot be computed for another organization's sector, see
 * <a href="https://openid.net/specs/openid-connect-core-1_0.html#PairwiseAlg">OpenID Connect Core 1.0, Section 8.1</a>
 * and <a href="https://openid.net/specs/openid-connect-registration-1_0.html#SectorIdentifierValidation">OpenID
 * Connect Dynamic Client Registration 1.0, Section 5</a>.
 * <p>
 * The client has a registration error, and is marked as invalid, when:
 * </p>
 * <ul>
 * <li>it has no {@code sector_identifier_uri} and its redirect URIs have more than one host. This needs no fetch and
 * is checked even when the {@code sector_identifier_uri} check is turned off;</li>
 * <li>the {@code sector_identifier_uri} does not use {@code https}, or the document it refers to is not a JSON array
 * holding all the client's redirect URIs;</li>
 * <li>the document cannot be fetched, unless the same {@code sector_identifier_uri} has been checked before for the
 * client, and only the redirect URIs have changed. Then the client stays valid. This mark is
 * {@link Outcome#temporary() temporary}.</li>
 * </ul>
 * <p>
 * A successful check is remembered as a {@link VerifiedSector}, and the document is not fetched again until the
 * combination of {@code sector_identifier_uri} and redirect URIs changes.
 * </p>
 *
 * @author Martin Lindström
 */
public class PairwiseClientCheck {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(PairwiseClientCheck.class);

  /** Fetches the document at the {@code sector_identifier_uri}, or {@code null} if the check is turned off. */
  private final SectorIdentifierFetcher fetcher;

  /**
   * Constructor.
   *
   * @param fetcher fetches the document at the {@code sector_identifier_uri}, or {@code null} to turn off the
   *     {@code sector_identifier_uri} check
   */
  public PairwiseClientCheck(final @Nullable SectorIdentifierFetcher fetcher) {
    this.fetcher = fetcher;
  }

  /**
   * Tells whether the document at the {@code sector_identifier_uri} is checked.
   *
   * @return {@code true} if the check is on and {@code false} otherwise
   */
  public boolean isSectorIdentifierUriChecked() {
    return this.fetcher != null;
  }

  /**
   * Checks the registration of a client. A client that is not pairwise is always valid.
   *
   * @param clientId the {@code client_id} of the client
   * @param metadata the client metadata
   * @param earlier the successful check that is remembered for the client, or {@code null}
   * @return the outcome
   */
  public @NonNull Outcome check(final @NonNull String clientId, final @NonNull OIDCClientMetadata metadata,
      final @Nullable VerifiedSector earlier) {
    Objects.requireNonNull(clientId, "clientId must not be null");
    Objects.requireNonNull(metadata, "metadata must not be null");

    if (!SubjectType.PAIRWISE.equals(metadata.getSubjectType())) {
      return Outcome.valid(null);
    }
    final List<URI> redirects = Objects.requireNonNullElse(metadata.getRedirectionURIs(), Set.<URI> of()).stream()
        .filter(Objects::nonNull)
        .toList();
    final URI sectorIdentifierUri = metadata.getSectorIDURI();

    if (sectorIdentifierUri == null) {
      final Set<String> hosts = redirects.stream()
          .map(URI::getHost)
          .filter(Objects::nonNull)
          .collect(Collectors.toSet());
      if (hosts.size() > 1) {
        return this.invalid(clientId, "the redirect_uris have %d different hosts and there is no sector_identifier_uri"
            .formatted(hosts.size()), false);
      }
      return Outcome.valid(null);
    }
    if (this.fetcher == null) {
      return Outcome.valid(earlier);
    }

    final String sector = sectorIdentifierUri.toString();
    final Set<String> redirectUris = redirects.stream()
        .map(URI::toString)
        .collect(Collectors.toCollection(LinkedHashSet::new));
    if (earlier != null && earlier.covers(sector, redirectUris)) {
      log.trace("The sector_identifier_uri of the client '{}' has been checked before", clientId);
      return Outcome.valid(earlier);
    }
    if (!"https".equalsIgnoreCase(sectorIdentifierUri.getScheme())) {
      return this.invalid(clientId, "the sector_identifier_uri does not use https", false);
    }

    final List<String> listed;
    try {
      listed = this.fetcher.fetch(sectorIdentifierUri);
    }
    catch (final IOException e) {
      if (earlier != null && earlier.sectorIdentifierUri().equals(sector)) {
        log.warn("The document at the sector_identifier_uri {} of the client '{}' cannot be fetched to check new "
            + "redirect_uris - the client stays valid: {}", sector, clientId, e.getMessage());
        return Outcome.valid(earlier);
      }
      return this.invalid(clientId,
          "the document at the sector_identifier_uri cannot be fetched: " + e.getMessage(), true);
    }
    if (listed == null) {
      return this.invalid(clientId, "the document at the sector_identifier_uri is not a JSON array of strings", false);
    }
    final List<String> missing = redirectUris.stream().filter(r -> !listed.contains(r)).toList();
    if (!missing.isEmpty()) {
      return this.invalid(clientId, "the document at the sector_identifier_uri does not list the redirect URI%s %s"
          .formatted(missing.size() > 1 ? "s" : "", String.join(", ", missing)), false);
    }
    log.debug("The document at the sector_identifier_uri {} of the client '{}' lists all its redirect URIs", sector,
        clientId);
    return Outcome.valid(new VerifiedSector(sector, redirectUris));
  }

  /**
   * Logs a registration error and creates the outcome for it.
   *
   * @param clientId the {@code client_id} of the client
   * @param reason why the client is invalid
   * @param temporary whether the mark is temporary
   * @return the outcome
   */
  private @NonNull Outcome invalid(final @NonNull String clientId, final @NonNull String reason,
      final boolean temporary) {
    log.warn("The pairwise client '{}' is marked as invalid{} - {}", clientId,
        temporary ? " for a while" : " until it is resolved again", reason);
    return new Outcome(reason, temporary, null);
  }

  /**
   * The outcome of a check.
   *
   * @param invalidReason why the client is invalid, or {@code null} if it is valid
   * @param temporary whether the client is invalid only for a while, since the document at its
   *     {@code sector_identifier_uri} could not be fetched. Otherwise an invalid client stays invalid until it is
   *     resolved again
   * @param verifiedSector the successful check to remember for the client, or {@code null}
   */
  public record Outcome(@Nullable String invalidReason, boolean temporary, @Nullable VerifiedSector verifiedSector) {

    /**
     * Creates the outcome for a valid client.
     *
     * @param verifiedSector the successful check to remember for the client, or {@code null}
     * @return the outcome
     */
    public static @NonNull Outcome valid(final @Nullable VerifiedSector verifiedSector) {
      return new Outcome(null, false, verifiedSector);
    }

    /**
     * Tells whether the client is valid.
     *
     * @return {@code true} if the client is valid and {@code false} otherwise
     */
    public boolean isValid() {
      return this.invalidReason == null;
    }
  }

}
