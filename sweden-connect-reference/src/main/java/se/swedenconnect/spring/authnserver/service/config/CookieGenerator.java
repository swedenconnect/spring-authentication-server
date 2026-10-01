/*
 * Copyright 2016-2026 Sweden Connect
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
package se.swedenconnect.spring.authnserver.service.config;

import java.time.Duration;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Writes and reads one cookie of the pages.
 *
 * @author Martin Lindström
 */
public class CookieGenerator {

  /** The cookie name. */
  private final String name;

  /** The cookie path. */
  private final String path;

  /** The lifetime of the cookie. */
  private final Duration maxAge;

  /**
   * Constructor.
   *
   * @param name the cookie name
   * @param path the cookie path, {@code /} if empty or {@code null}
   * @param maxAge the lifetime of the cookie
   */
  public CookieGenerator(final @NonNull String name, final @Nullable String path, final @NonNull Duration maxAge) {
    this.name = Objects.requireNonNull(name, "name must not be null");
    this.path = path == null || path.isBlank() ? "/" : path;
    this.maxAge = Objects.requireNonNull(maxAge, "maxAge must not be null");
  }

  /**
   * Gets the cookie name.
   *
   * @return the cookie name
   */
  public @NonNull String getName() {
    return this.name;
  }

  /**
   * Adds the cookie to the response.
   *
   * @param value the value of the cookie
   * @param response the HTTP servlet response
   */
  public void addCookie(final @NonNull String value, final @NonNull HttpServletResponse response) {
    response.addHeader(HttpHeaders.SET_COOKIE, this.builder(value).maxAge(this.maxAge).build().toString());
  }

  /**
   * Removes the cookie from the browser.
   *
   * @param response the HTTP servlet response
   */
  public void clearCookie(final @NonNull HttpServletResponse response) {
    response.addHeader(HttpHeaders.SET_COOKIE, this.builder("").maxAge(Duration.ZERO).build().toString());
  }

  /**
   * Gets the value of the cookie from a request.
   *
   * @param request the HTTP servlet request
   * @return the value, or {@code null} if the request does not carry the cookie
   */
  public @Nullable String getValue(final @NonNull HttpServletRequest request) {
    final Cookie[] cookies = request.getCookies();
    if (cookies == null) {
      return null;
    }
    for (final Cookie cookie : cookies) {
      if (this.name.equals(cookie.getName())) {
        return cookie.getValue();
      }
    }
    return null;
  }

  /**
   * Creates a cookie builder.
   *
   * @param value the value
   * @return a builder
   */
  private ResponseCookie.@NonNull ResponseCookieBuilder builder(final @NonNull String value) {
    return ResponseCookie.from(this.name, value)
        .path(this.path)
        .httpOnly(true)
        .secure(true);
  }

}
