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
package se.swedenconnect.spring.authnserver.service;

import java.io.InputStream;
import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.springframework.core.io.ClassPathResource;
import org.springframework.web.util.HtmlUtils;

/**
 * A browser for the tests: keeps cookies, trusts the TLS certificate of the test profile, and lets the test follow
 * redirects one at a time.
 *
 * @author Martin Lindström
 */
final class TestBrowser {

  /** The SSL context that trusts the TLS certificate of the test profile. */
  static final SSLContext SSL_CONTEXT = createSslContext();

  /** What the browser accepts. */
  private static final String ACCEPT = "text/html,application/xhtml+xml,*/*;q=0.8";

  /** The HTTP client. */
  private final HttpClient client;

  /**
   * Constructor.
   */
  TestBrowser() {
    this.client = HttpClient.newBuilder()
        .sslContext(SSL_CONTEXT)
        .cookieHandler(new CookieManager(null, CookiePolicy.ACCEPT_ALL))
        .followRedirects(HttpClient.Redirect.NEVER)
        .build();
  }

  /**
   * Sends a GET request.
   */
  HttpResponse<String> get(final String url) throws Exception {
    return this.get(url, ACCEPT);
  }

  /**
   * Sends a GET request with the supplied Accept header.
   */
  HttpResponse<String> get(final String url, final String accept) throws Exception {
    return this.client.send(HttpRequest.newBuilder(URI.create(url)).header("Accept", accept).GET().build(),
        HttpResponse.BodyHandlers.ofString());
  }

  /**
   * Sends a form with POST.
   */
  HttpResponse<String> post(final String url, final Map<String, String> form) throws Exception {
    final String body = form.entrySet().stream()
        .map(e -> URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8) + "="
            + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
        .collect(Collectors.joining("&"));
    return this.client.send(HttpRequest.newBuilder(URI.create(url))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Accept", ACCEPT)
        .POST(HttpRequest.BodyPublishers.ofString(body))
        .build(), HttpResponse.BodyHandlers.ofString());
  }

  /**
   * Follows redirects, as long as they go to the server under test, and returns the first response that is not a
   * redirect, or a redirect away from the server.
   */
  HttpResponse<String> follow(final HttpResponse<String> response, final String baseUrl) throws Exception {
    HttpResponse<String> current = response;
    while (isRedirect(current)) {
      final String location = location(current);
      if (!location.startsWith(baseUrl)) {
        return current;
      }
      current = this.get(location);
    }
    return current;
  }

  /**
   * Tells whether the response is a redirect.
   */
  static boolean isRedirect(final HttpResponse<String> response) {
    return response.statusCode() >= 300 && response.statusCode() < 400;
  }

  /**
   * Gets the absolute URL that a redirect points to.
   */
  static String location(final HttpResponse<String> response) {
    final String location = response.headers().firstValue("Location")
        .orElseThrow(() -> new IllegalStateException("No Location header"));
    return response.uri().resolve(location).toString();
  }

  /**
   * Gets the value of an input field of a page.
   */
  static String inputValue(final String html, final String name) {
    final Matcher matcher = Pattern.compile("<input[^>]*name=\"" + Pattern.quote(name) + "\"[^>]*>").matcher(html);
    while (matcher.find()) {
      final Matcher value = Pattern.compile("value=\"([^\"]*)\"").matcher(matcher.group());
      if (value.find()) {
        return HtmlUtils.htmlUnescape(value.group(1));
      }
    }
    return null;
  }

  /**
   * Gets the action of the first form of a page that posts.
   */
  static String formAction(final String html) {
    final Matcher matcher = Pattern.compile("<form[^>]*>").matcher(html);
    while (matcher.find()) {
      final String form = matcher.group();
      final Matcher action = Pattern.compile("action=\"([^\"]*)\"").matcher(form);
      if (form.toUpperCase().contains("METHOD=\"POST\"") && action.find()) {
        return HtmlUtils.htmlUnescape(action.group(1));
      }
    }
    return null;
  }

  /**
   * Gets the start tag of the element with the given id.
   */
  static String startTag(final String html, final String id) {
    final Matcher matcher = Pattern.compile("<[a-z]+[^>]*id=\"" + Pattern.quote(id) + "\"[^>]*>").matcher(html);
    return matcher.find() ? matcher.group() : null;
  }

  /**
   * Gets the values of the options of the select element with the given id.
   */
  static List<String> optionValues(final String html, final String id) {
    final int start = html.indexOf("id=\"" + id + "\"");
    if (start < 0) {
      return List.of();
    }
    final String select = html.substring(start, html.indexOf("</select>", start));
    final List<String> values = new ArrayList<>();
    final Matcher matcher = Pattern.compile("<option[^>]*value=\"([^\"]*)\"").matcher(select);
    while (matcher.find()) {
      values.add(HtmlUtils.htmlUnescape(matcher.group(1)));
    }
    return values;
  }

  /**
   * Gets the value of the selected option of the select element with the given id.
   */
  static String selectedOption(final String html, final String id) {
    final int start = html.indexOf("id=\"" + id + "\"");
    if (start < 0) {
      return null;
    }
    final String select = html.substring(start, html.indexOf("</select>", start));
    final Matcher matcher = Pattern.compile("<option\\s+value=\"([^\"]*)\"\\s+selected=\"selected\"").matcher(select);
    return matcher.find() ? HtmlUtils.htmlUnescape(matcher.group(1)) : null;
  }

  /**
   * Gets the parameters of a URL query.
   */
  static Map<String, String> queryParameters(final String url) {
    final String query = URI.create(url).getRawQuery();
    if (query == null) {
      return Map.of();
    }
    return java.util.Arrays.stream(query.split("&"))
        .map(p -> p.split("=", 2))
        .collect(Collectors.toMap(p -> java.net.URLDecoder.decode(p[0], StandardCharsets.UTF_8),
            p -> p.length > 1 ? java.net.URLDecoder.decode(p[1], StandardCharsets.UTF_8) : ""));
  }

  private static SSLContext createSslContext() {
    try (final InputStream is = new ClassPathResource("complete/tls.p12").getInputStream()) {
      final KeyStore trust = KeyStore.getInstance("PKCS12");
      trust.load(is, "secret".toCharArray());
      final TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
      tmf.init(trust);
      final SSLContext context = SSLContext.getInstance("TLS");
      context.init(null, tmf.getTrustManagers(), null);
      return context;
    }
    catch (final Exception e) {
      throw new IllegalStateException(e);
    }
  }

}
