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
package se.swedenconnect.spring.authnserver.service.config;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.servlet.support.RequestContextUtils;
import org.thymeleaf.context.WebContext;
import org.thymeleaf.spring6.SpringTemplateEngine;
import org.thymeleaf.web.servlet.JakartaServletWebApplication;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import se.swedenconnect.spring.authnserver.saml.response.ResponsePage;

/**
 * The page that posts a response to the requester, rendered from a Thymeleaf template so that it looks like the other
 * pages. It posts SAML responses (the HTTP POST binding), and OpenID Connect responses in the {@code form_post}
 * response mode.
 * <p>
 * The template gets the URL to post to as {@code action}, and the parameters to post as {@code parameters}, a map
 * of name to value.
 * </p>
 *
 * @author Martin Lindström
 */
public class ThymeleafResponsePage
    implements ResponsePage, se.swedenconnect.spring.authnserver.oidc.response.ResponsePage {

  /** The content type of the page. */
  private static final MediaType TEXT_HTML_UTF8 = new MediaType("text", "html", StandardCharsets.UTF_8);

  /** The template engine. */
  private final SpringTemplateEngine templateEngine;

  /** The name of the template. */
  private final String templateName;

  /**
   * Constructor.
   *
   * @param templateEngine the template engine
   * @param templateName the name of the template
   */
  public ThymeleafResponsePage(final @NonNull SpringTemplateEngine templateEngine,
      final @NonNull String templateName) {
    this.templateEngine = Objects.requireNonNull(templateEngine, "templateEngine must not be null");
    this.templateName = Objects.requireNonNull(templateName, "templateName must not be null");
  }

  /**
   * Writes the page that posts a SAML response.
   */
  @Override
  public void sendResponse(final @NonNull HttpServletRequest httpServletRequest,
      final @NonNull HttpServletResponse httpServletResponse, final @NonNull String destination,
      final @NonNull String samlResponse, final @Nullable String relayState) throws IOException {
    final Map<String, String> parameters = new LinkedHashMap<>();
    parameters.put("SAMLResponse", samlResponse);
    if (relayState != null) {
      parameters.put("RelayState", relayState);
    }
    this.sendResponse(httpServletRequest, httpServletResponse, destination, parameters);
  }

  /**
   * Writes the page that posts an OpenID Connect response, and is also used for the SAML response.
   */
  @Override
  public void sendResponse(final @NonNull HttpServletRequest httpServletRequest,
      final @NonNull HttpServletResponse httpServletResponse, final @NonNull String destination,
      final @NonNull Map<String, String> parameters) throws IOException {

    final JakartaServletWebApplication application =
        JakartaServletWebApplication.buildApplication(httpServletRequest.getServletContext());
    final WebContext context = new WebContext(application.buildExchange(httpServletRequest, httpServletResponse),
        RequestContextUtils.getLocale(httpServletRequest));
    context.setVariable("action", destination);
    context.setVariable("parameters", parameters);

    httpServletResponse.setContentType(TEXT_HTML_UTF8.toString());
    httpServletResponse.setHeader(HttpHeaders.CACHE_CONTROL, "no-cache, no-store");
    httpServletResponse.setHeader(HttpHeaders.PRAGMA, "no-cache");
    this.templateEngine.process(this.templateName, context, httpServletResponse.getWriter());
  }

}
