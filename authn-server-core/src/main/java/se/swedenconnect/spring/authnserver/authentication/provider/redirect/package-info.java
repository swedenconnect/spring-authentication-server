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
/**
 * The redirect authentication flow, for modules that authenticate the user on pages of their own. The user is sent out
 * of the Spring Security flow to the module's controller and returns to the resume path when the authentication is
 * done.
 */
package se.swedenconnect.spring.authnserver.authentication.provider.redirect;
