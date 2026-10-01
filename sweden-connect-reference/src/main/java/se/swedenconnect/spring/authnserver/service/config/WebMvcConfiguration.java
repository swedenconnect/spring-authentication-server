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
import java.util.Locale;

import org.jspecify.annotations.NonNull;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.i18n.CookieLocaleResolver;
import org.springframework.web.servlet.i18n.LocaleChangeInterceptor;

/**
 * Web MVC configuration: the language of the pages is chosen with the {@code lang} parameter and remembered in a
 * cookie.
 *
 * @author Martin Lindström
 */
@Configuration(proxyBeanMethods = false)
public class WebMvcConfiguration implements WebMvcConfigurer {

  /**
   * Creates the {@link LocaleResolver} that remembers the language of the pages in a cookie. The default language is
   * English.
   *
   * @param contextPath the servlet context path
   * @return a {@link LocaleResolver}
   */
  @Bean
  LocaleResolver localeResolver(@Value("${server.servlet.context-path:}") final @NonNull String contextPath) {
    final CookieLocaleResolver resolver = new CookieLocaleResolver();
    resolver.setDefaultLocale(Locale.ENGLISH);
    resolver.setCookiePath(contextPath.isBlank() ? "/" : contextPath);
    resolver.setCookieMaxAge(Duration.ofDays(365));
    return resolver;
  }

  /**
   * Adds the interceptor that changes the language when a request carries the {@code lang} parameter.
   */
  @Override
  public void addInterceptors(final @NonNull InterceptorRegistry registry) {
    final LocaleChangeInterceptor interceptor = new LocaleChangeInterceptor();
    interceptor.setParamName("lang");
    registry.addInterceptor(interceptor);
  }

}
