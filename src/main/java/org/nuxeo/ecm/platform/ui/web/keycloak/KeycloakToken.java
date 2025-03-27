/*
 * (C) Copyright 2024 Nuxeo (http://nuxeo.com/) and others.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.nuxeo.ecm.platform.ui.web.keycloak;

import com.fasterxml.jackson.annotation.JsonProperty;

/** @since 2023.10 */
public record KeycloakToken(@JsonProperty("access_token") String accessToken, @JsonProperty("expires_in") int expiresIn,
        @JsonProperty("refresh_expires_in") int refreshExpiresIn, @JsonProperty("token_type") String tokenType,
        @JsonProperty("id_token") String idToken, @JsonProperty("not-before-policy") int notBeforePolicy,
        String scope) {
}
