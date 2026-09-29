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
package se.swedenconnect.spring.authnserver.saml.metadata;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;

import java.io.File;
import java.security.cert.X509Certificate;
import java.util.Objects;

import org.springframework.core.io.Resource;

/**
 * One source of SAML metadata.
 * <p>
 * The location decides how the source is read. A URL that is not a file is downloaded over HTTP, either as a
 * federation metadata document or, when {@link #mdq()} is set, through the
 * <a href="https://www.ietf.org/id/draft-young-md-query-17.html">MDQ protocol</a>. A file is read from the file
 * system, and anything else, such as a classpath resource, is read once and held in memory.
 * </p>
 *
 * @param location where the metadata is found. A URL, a file or any other resource
 * @param httpsTrustBundle the name of the
 *          <a href="https://spring.io/blog/2023/06/07/securing-spring-boot-applications-with-ssl">Spring SSL
 *          bundle</a> holding the TLS trust to use, or {@code null} to use the Java default. Only used when the
 *          location is an HTTPS URL
 * @param skipHostnameVerification whether TLS hostname verification is skipped. Useful while testing
 * @param backupLocation where downloaded metadata is stored, so that the Identity Provider can start even when the
 *          source cannot be reached. A file for a federation metadata source and a directory for an MDQ source
 * @param mdq whether the source is queried with the MDQ protocol
 * @param validationCertificate the certificate that the metadata signature is validated against
 * @param httpProxy the HTTP proxy to use, or {@code null} for no proxy
 * @author Martin Lindström
 */
public record MetadataSource(
    @Nonnull Resource location,
    @Nullable String httpsTrustBundle,
    boolean skipHostnameVerification,
    @Nullable File backupLocation,
    boolean mdq,
    @Nullable X509Certificate validationCertificate,
    @Nullable HttpProxy httpProxy) {

  /**
   * Constructor.
   *
   * @param location where the metadata is found
   * @param httpsTrustBundle the name of the Spring SSL bundle holding the TLS trust to use, or {@code null}
   * @param skipHostnameVerification whether TLS hostname verification is skipped
   * @param backupLocation where downloaded metadata is stored, or {@code null}
   * @param mdq whether the source is queried with the MDQ protocol
   * @param validationCertificate the metadata signature validation certificate, or {@code null}
   * @param httpProxy the HTTP proxy to use, or {@code null}
   */
  public MetadataSource {
    Objects.requireNonNull(location, "location must not be null");
  }

  /**
   * Creates a builder.
   *
   * @param location where the metadata is found
   * @return a {@link Builder}
   */
  public static @Nonnull Builder builder(final @Nonnull Resource location) {
    return new Builder(location);
  }

  /**
   * An HTTP proxy.
   *
   * @param host the proxy host
   * @param port the proxy port
   * @param userName the user name, or {@code null} if the proxy needs no authentication
   * @param password the password, or {@code null} if the proxy needs no authentication
   */
  public record HttpProxy(@Nonnull String host, int port, @Nullable String userName, @Nullable String password) {

    /**
     * Constructor.
     *
     * @param host the proxy host
     * @param port the proxy port
     * @param userName the user name, or {@code null}
     * @param password the password, or {@code null}
     */
    public HttpProxy {
      Objects.requireNonNull(host, "host must not be null");
      if (port <= 0) {
        throw new IllegalArgumentException("port must be a positive number");
      }
    }

  }

  /**
   * A builder for {@link MetadataSource} objects.
   */
  public static final class Builder {

    /** Where the metadata is found. */
    private final Resource location;

    /** The name of the SSL bundle holding the TLS trust. */
    private String httpsTrustBundle;

    /** Whether TLS hostname verification is skipped. */
    private boolean skipHostnameVerification = false;

    /** Where downloaded metadata is stored. */
    private File backupLocation;

    /** Whether the source is queried with the MDQ protocol. */
    private boolean mdq = false;

    /** The metadata signature validation certificate. */
    private X509Certificate validationCertificate;

    /** The HTTP proxy to use. */
    private HttpProxy httpProxy;

    /**
     * Constructor.
     *
     * @param location where the metadata is found
     */
    private Builder(final @Nonnull Resource location) {
      this.location = Objects.requireNonNull(location, "location must not be null");
    }

    /**
     * Assigns the name of the Spring SSL bundle holding the TLS trust to use.
     *
     * @param httpsTrustBundle the bundle name
     * @return the builder
     */
    public @Nonnull Builder httpsTrustBundle(final @Nullable String httpsTrustBundle) {
      this.httpsTrustBundle = httpsTrustBundle;
      return this;
    }

    /**
     * Assigns whether TLS hostname verification is skipped.
     *
     * @param skipHostnameVerification whether verification is skipped
     * @return the builder
     */
    public @Nonnull Builder skipHostnameVerification(final boolean skipHostnameVerification) {
      this.skipHostnameVerification = skipHostnameVerification;
      return this;
    }

    /**
     * Assigns where downloaded metadata is stored.
     *
     * @param backupLocation a file for a federation metadata source and a directory for an MDQ source
     * @return the builder
     */
    public @Nonnull Builder backupLocation(final @Nullable File backupLocation) {
      this.backupLocation = backupLocation;
      return this;
    }

    /**
     * Assigns whether the source is queried with the MDQ protocol.
     *
     * @param mdq whether MDQ is used
     * @return the builder
     */
    public @Nonnull Builder mdq(final boolean mdq) {
      this.mdq = mdq;
      return this;
    }

    /**
     * Assigns the certificate that the metadata signature is validated against.
     *
     * @param validationCertificate the validation certificate
     * @return the builder
     */
    public @Nonnull Builder validationCertificate(final @Nullable X509Certificate validationCertificate) {
      this.validationCertificate = validationCertificate;
      return this;
    }

    /**
     * Assigns the HTTP proxy to use.
     *
     * @param httpProxy the proxy
     * @return the builder
     */
    public @Nonnull Builder httpProxy(final @Nullable HttpProxy httpProxy) {
      this.httpProxy = httpProxy;
      return this;
    }

    /**
     * Builds the metadata source.
     *
     * @return a {@link MetadataSource}
     */
    public @Nonnull MetadataSource build() {
      return new MetadataSource(this.location, this.httpsTrustBundle, this.skipHostnameVerification,
          this.backupLocation, this.mdq, this.validationCertificate, this.httpProxy);
    }

  }

}
