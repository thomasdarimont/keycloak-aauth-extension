/*
 * Copyright 2025 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.protocol.aauth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import org.junit.jupiter.api.Test;
import org.keycloak.jose.jwk.JWKBuilder;
import org.keycloak.util.JsonSerialization;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.net.CookieManager;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Exercises the curl examples from the README against a real Keycloak
 * with the extension deployed as a provider.
 */
@Testcontainers
class ReadmeExamplesIT {

    static final String REALM = "master";

    @Container
    static final KeycloakContainer keycloak = new KeycloakContainer("quay.io/keycloak/keycloak:26.7.4")
            .withProviderClassesFrom("target/classes");

    // HTTP/1.1 so the Host header is sent as a real header: the signed requests cover
    // @authority, which the server resolves from the Host header (with HTTP/2 it would
    // travel as the :authority pseudo-header instead and signature verification fails)
    final HttpClient http = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).build();
    final ObjectMapper mapper = new ObjectMapper();

    String baseUrl() {
        String url = keycloak.getAuthServerUrl();
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }

    // README: curl https://keycloak.example.com/realms/{realm}/.well-known/aauth-issuer
    // (the provider's alias is "aauth-issuer.json", so that is the actual path)
    @Test
    void wellKnownEndpointServesIssuerMetadata() throws Exception {
        HttpResponse<String> response = http.send(
                HttpRequest.newBuilder(URI.create(baseUrl() + "/realms/" + REALM + "/.well-known/aauth-issuer.json"))
                        .GET().build(),
                HttpResponse.BodyHandlers.ofString());

        assertEquals(200, response.statusCode());

        JsonNode metadata = mapper.readTree(response.body());
        assertEquals(baseUrl() + "/realms/" + REALM, metadata.get("issuer").asText());
        assertTrue(metadata.hasNonNull("jwks_uri"));
        assertTrue(metadata.hasNonNull("agent_token_endpoint"));

        List<String> requestTypes = mapper.convertValue(metadata.get("request_types_supported"),
                mapper.getTypeFactory().constructCollectionType(List.class, String.class));
        // README: grant types auth, code, refresh, exchange
        assertTrue(requestTypes.containsAll(List.of("auth", "code", "refresh", "exchange")),
                "request_types_supported was: " + requestTypes);
    }

    // README: enable AAuth via Admin API:
    // curl -X PUT ".../admin/realms/{realm}" -d '{"attributes": {"aauth.enabled": "true"}}'
    @Test
    void enableAAuthViaAdminApi() throws Exception {
        String token = adminAccessToken();

        HttpResponse<String> update = http.send(
                HttpRequest.newBuilder(URI.create(baseUrl() + "/admin/realms/" + REALM))
                        .header("Authorization", "Bearer " + token)
                        .header("Content-Type", "application/json")
                        .PUT(HttpRequest.BodyPublishers.ofString(
                                "{\"attributes\": {\"aauth.enabled\": \"true\"}}"))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(204, update.statusCode(), "body: " + update.body());

        HttpResponse<String> realm = http.send(
                HttpRequest.newBuilder(URI.create(baseUrl() + "/admin/realms/" + REALM))
                        .header("Authorization", "Bearer " + token)
                        .GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, realm.statusCode());
        assertEquals("true", mapper.readTree(realm.body()).path("attributes").path("aauth.enabled").asText());
    }

    // README: direct grant token request against
    // POST /realms/{realm}/protocol/aauth/agent/token
    // Without the HTTPSig signature headers the request must be rejected.
    @Test
    void unsignedTokenRequestIsRejected() throws Exception {
        String form = formEncode(Map.of(
                "grant_type", "auth",
                "scope", "read write",
                "resource_id", "https://resource.example.com"));

        HttpResponse<String> response = http.send(
                HttpRequest.newBuilder(URI.create(baseUrl() + "/realms/" + REALM + "/protocol/aauth/agent/token"))
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(form))
                        .build(),
                HttpResponse.BodyHandlers.ofString());

        assertEquals(401, response.statusCode(), "body: " + response.body());
        assertEquals("invalid_request", mapper.readTree(response.body()).path("error").asText());
    }

    // README: signed direct grant (no user consent):
    // POST /realms/{realm}/protocol/aauth/agent/token with Signature-Key/Signature-Input/Signature
    // headers and grant_type=auth&scope=read write. The scopes do not require consent,
    // so an auth_token is issued directly.
    @Test
    void signedDirectGrantIssuesAuthToken() throws Exception {
        HttpMessageSigner agent = new HttpMessageSigner();
        String form = formEncode(Map.of(
                "grant_type", "auth",
                "scope", "read write",
                "resource_id", "https://resource.example.com"));

        HttpResponse<String> response = http.send(
                agent.signedPost(baseUrl() + "/realms/" + REALM + "/protocol/aauth/agent/token", form),
                HttpResponse.BodyHandlers.ofString());

        assertEquals(200, response.statusCode(), "body: " + response.body());
        JsonNode token = mapper.readTree(response.body());
        assertEquals(3, token.get("auth_token").asText().split("\\.").length, "auth_token should be a JWT");
        assertTrue(token.get("expires_in").asInt() > 0);
    }

    // README: authorization code flow (with user consent).
    // A consent-requiring scope (openid) yields a pending interaction (202) whose code
    // is used for Step 1: GET /realms/{realm}/protocol/aauth/agent/auth?code=...
    // which must redirect the user agent to the Keycloak login page.
    @Test
    void signedConsentFlowRedirectsUserToLogin() throws Exception {
        HttpMessageSigner agent = new HttpMessageSigner();
        String form = formEncode(Map.of(
                "grant_type", "auth",
                "scope", "openid",
                "redirect_uri", "https://agent.example.com/callback"));

        HttpResponse<String> pending = http.send(
                agent.signedPost(baseUrl() + "/realms/" + REALM + "/protocol/aauth/agent/token", form),
                HttpResponse.BodyHandlers.ofString());

        assertEquals(202, pending.statusCode(), "body: " + pending.body());
        JsonNode body = mapper.readTree(pending.body());
        assertEquals("pending", body.get("status").asText());
        assertEquals("interaction", body.get("require").asText());
        String interactionCode = body.get("code").asText();
        assertFalse(interactionCode.isEmpty());

        // Step 1: the interaction URL accepts the code and sends the user agent to login
        HttpClient browser = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .followRedirects(HttpClient.Redirect.NEVER)
                .cookieHandler(new CookieManager())
                .build();
        HttpResponse<String> interaction = browser.send(
                HttpRequest.newBuilder(URI.create(baseUrl() + "/realms/" + REALM
                                + "/protocol/aauth/agent/auth?code=" + interactionCode))
                        .GET().build(),
                HttpResponse.BodyHandlers.ofString());

        assertEquals(303, interaction.statusCode(), "body: " + interaction.body());
        String location = interaction.headers().firstValue("Location").orElse("");
        assertTrue(location.contains("/login-actions/authenticate"),
                "expected a redirect to the login page, got: " + location);
        assertTrue(location.contains("tab_id="),
                "login redirect should carry the authentication session tab_id: " + location);
    }

    // An unknown interaction code must not start a consent flow.
    @Test
    void interactionEndpointRejectsUnknownCode() throws Exception {
        HttpResponse<String> response = http.send(
                HttpRequest.newBuilder(URI.create(baseUrl() + "/realms/" + REALM
                                + "/protocol/aauth/agent/auth?code=bogus-interaction-code"))
                        .GET().build(),
                HttpResponse.BodyHandlers.ofString());

        assertEquals(400, response.statusCode());
        assertTrue(response.body().contains("Invalid or expired interaction code"),
                "body: " + response.body());
    }

    // README: Step 2 exchanges the code for a token. An unknown code must be rejected
    // with invalid_grant (a valid code only exists after user consent in a browser).
    // Note: the token endpoint routes on request_type (the README's grant_type is legacy).
    @Test
    void signedCodeExchangeRejectsUnknownCode() throws Exception {
        HttpMessageSigner agent = new HttpMessageSigner();
        String form = formEncode(Map.of(
                "request_type", "code",
                "code", "bogus-authorization-code"));

        HttpResponse<String> response = http.send(
                agent.signedPost(baseUrl() + "/realms/" + REALM + "/protocol/aauth/agent/token", form),
                HttpResponse.BodyHandlers.ofString());

        assertEquals(400, response.statusCode(), "body: " + response.body());
        assertEquals("invalid_grant", mapper.readTree(response.body()).path("error").asText(),
                "body: " + response.body());
    }

    /**
     * Minimal RFC 9421 HTTP Message Signatures client using the AAuth "hwk" scheme:
     * an Ed25519 key carried directly in the Signature-Key header (pseudonymous agent).
     * The signature base mirrors the server-side SignatureBaseBuilder.
     */
    static class HttpMessageSigner {

        private static final String LABEL = "sig";
        private static final List<String> COMPONENTS = List.of(
                "@method", "@authority", "@path", "content-type", "content-digest", "signature-key");

        private final KeyPair keyPair;
        private final String signatureKeyHeader;

        HttpMessageSigner() throws Exception {
            this.keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
            JsonNode jwk = new ObjectMapper().readTree(
                    JsonSerialization.writeValueAsString(JWKBuilder.create().okp(keyPair.getPublic())));
            this.signatureKeyHeader = LABEL + "=hwk;kty=\"OKP\";crv=\"Ed25519\";x=\"" + jwk.get("x").asText() + "\"";
        }

        HttpRequest signedPost(String url, String form) throws Exception {
            URI uri = URI.create(url);
            byte[] body = form.getBytes(StandardCharsets.UTF_8);
            String contentType = "application/x-www-form-urlencoded";
            String contentDigest = "sha-256=:"
                    + Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(body)) + ":";

            long created = System.currentTimeMillis() / 1000;
            String signatureParams = COMPONENTS.stream()
                    .map(c -> "\"" + c + "\"")
                    .collect(Collectors.joining(" ", "(", ")")) + ";created=" + created;

            String authority = uri.getHost() + (uri.getPort() > 0 ? ":" + uri.getPort() : "");
            Map<String, String> componentValues = Map.of(
                    "@method", "POST",
                    "@authority", authority,
                    "@path", uri.getPath(),
                    "content-type", contentType,
                    "content-digest", contentDigest,
                    "signature-key", signatureKeyHeader);

            String signatureBase = COMPONENTS.stream()
                    .map(c -> "\"" + c + "\": " + componentValues.get(c))
                    .collect(Collectors.joining("\n"))
                    + "\n\"@signature-params\": " + signatureParams;

            Signature signer = Signature.getInstance("Ed25519");
            signer.initSign(keyPair.getPrivate());
            signer.update(signatureBase.getBytes(StandardCharsets.UTF_8));
            String signature = Base64.getEncoder().encodeToString(signer.sign());

            return HttpRequest.newBuilder(uri)
                    .header("Content-Type", contentType)
                    .header("Content-Digest", contentDigest)
                    .header("Signature-Key", signatureKeyHeader)
                    .header("Signature-Input", LABEL + "=" + signatureParams)
                    .header("Signature", LABEL + "=:" + signature + ":")
                    .POST(HttpRequest.BodyPublishers.ofByteArray(body))
                    .build();
        }
    }

    private String adminAccessToken() throws Exception {
        String form = formEncode(Map.of(
                "grant_type", "password",
                "client_id", "admin-cli",
                "username", keycloak.getAdminUsername(),
                "password", keycloak.getAdminPassword()));

        HttpResponse<String> response = http.send(
                HttpRequest.newBuilder(URI.create(baseUrl() + "/realms/master/protocol/openid-connect/token"))
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(form))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode(), "body: " + response.body());
        return mapper.readTree(response.body()).get("access_token").asText();
    }

    private static String formEncode(Map<String, String> params) {
        return params.entrySet().stream()
                .map(e -> e.getKey() + "=" + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
                .collect(Collectors.joining("&"));
    }
}
