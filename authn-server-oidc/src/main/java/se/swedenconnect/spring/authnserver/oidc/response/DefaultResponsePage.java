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
package se.swedenconnect.spring.authnserver.oidc.response;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import org.jspecify.annotations.NonNull;
import org.springframework.web.util.HtmlUtils;

/**
 * The default {@link ResponsePage}: a plain HTML page with a form that is posted automatically, and a button for
 * browsers without JavaScript.
 *
 * @author Martin Lindström
 */
public class DefaultResponsePage implements ResponsePage {

  /** Line separator. */
  private static final String NEWLINE = System.lineSeparator();

  /** {@inheritDoc} */
  @Override
  public void sendResponse(final @NonNull HttpServletRequest httpServletRequest,
      final @NonNull HttpServletResponse httpServletResponse, final @NonNull String destination,
      final @NonNull Map<String, String> parameters) throws IOException {

    final String page = generateResponsePage(destination, parameters);
    httpServletResponse.setContentType("text/html;charset=UTF-8");
    httpServletResponse.setContentLength(page.getBytes(StandardCharsets.UTF_8).length);
    httpServletResponse.setHeader("Cache-Control", "no-cache, no-store");
    httpServletResponse.setHeader("Pragma", "no-cache");
    httpServletResponse.getWriter().write(page);
  }

  /**
   * Generates the response page.
   *
   * @param destination the redirect URI that the response is posted to
   * @param parameters the response parameters
   * @return the HTML page
   */
  public static @NonNull String generateResponsePage(final @NonNull String destination,
      final @NonNull Map<String, String> parameters) {

    final StringBuilder builder = new StringBuilder();
    builder.append("<!DOCTYPE html>").append(NEWLINE);
    builder.append("<html lang=\"en\">").append(NEWLINE);
    builder.append("<head>").append(NEWLINE);
    builder.append("  <meta charset=\"utf-8\">").append(NEWLINE);
    builder.append("  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1, shrink-to-fit=no\">")
        .append(NEWLINE);
    builder.append("  <title>OpenID Connect Response</title>").append(NEWLINE);
    builder.append("</head>").append(NEWLINE);
    builder.append("<body onload=\"document.forms[0].submit()\">").append(NEWLINE);
    builder.append("  <form action=\"").append(escape(destination)).append("\" method=\"POST\">").append(NEWLINE);
    parameters.forEach((name, value) -> builder.append("    <input type=\"hidden\" name=\"").append(escape(name))
        .append("\" value=\"").append(escape(value)).append("\" />").append(NEWLINE));
    builder.append("    <noscript>").append(NEWLINE);
    builder.append("      <p>Your web browser does not have JavaScript enabled. Click the \"Continue\" button below "
        + "to proceed.</p>").append(NEWLINE);
    builder.append("      <p><input type=\"submit\" value=\"Continue\" /></p>").append(NEWLINE);
    builder.append("    </noscript>").append(NEWLINE);
    builder.append("  </form>").append(NEWLINE);
    builder.append("</body>").append(NEWLINE);
    builder.append("</html>").append(NEWLINE);
    return builder.toString();
  }

  /**
   * Escapes an HTML attribute value.
   *
   * @param value the value
   * @return the escaped value
   */
  private static @NonNull String escape(final @NonNull String value) {
    return HtmlUtils.htmlEscape(value, StandardCharsets.UTF_8.name());
  }

}
