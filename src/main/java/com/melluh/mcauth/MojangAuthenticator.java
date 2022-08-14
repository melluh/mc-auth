package com.melluh.mcauth;

import com.grack.nanojson.JsonObject;
import com.grack.nanojson.JsonParser;
import com.grack.nanojson.JsonParserException;
import com.grack.nanojson.JsonWriter;
import com.melluh.mcauth.tokens.MojangToken;
import com.melluh.mcauth.tokens.XboxToken;
import com.melluh.mcauth.utils.AuthUtils;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

public class MojangAuthenticator {

    private static final URI AUTH_URI = URI.create("https://api.minecraftservices.com/authentication/login_with_xbox");
    private static final URI PROFILE_URI = URI.create("https://api.minecraftservices.com/minecraft/profile");
    private static final URI SESSION_JOIN_URI = URI.create("https://sessionserver.mojang.com/session/minecraft/join");

    private static final String IDENTITY_TOKEN_FORMAT = "XBL3.0 x=%s;%s";

    private final HttpClient httpClient;

    private MojangAuthenticator(HttpClient httpClient) {
        this.httpClient = httpClient;
    }

    public CompletableFuture<MojangToken> getAccessToken(XboxToken xstsToken) {
        return CompletableFuture.supplyAsync(() -> {
            JsonObject reqJson = JsonObject.builder()
                    .value("identityToken", String.format(IDENTITY_TOKEN_FORMAT, xstsToken.getUserHash(), xstsToken.getValue()))
                    .done();

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(AUTH_URI)
                    .POST(BodyPublishers.ofString(JsonWriter.string(reqJson)))
                    .build();

            try {
                HttpResponse<String> response = httpClient.send(request, BodyHandlers.ofString());
                JsonObject json = JsonParser.object().from(response.body());

                long expiryTime = System.currentTimeMillis() + json.getInt("expires_in") * 1000L;
                return new MojangToken(json.getString("access_token"), expiryTime);
            } catch (IOException | InterruptedException | JsonParserException ex) {
                throw new AuthenticationException("Authentication request to Mojang failed", ex);
            }
        });
    }

    public CompletableFuture<GameProfile> getProfile(MojangToken mojangToken) {
        return CompletableFuture.supplyAsync(() -> {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(PROFILE_URI)
                    .header("Authorization", "Bearer " + mojangToken.getValue())
                    .build();

            try {
                HttpResponse<String> response = httpClient.send(request, BodyHandlers.ofString());
                JsonObject json = JsonParser.object().from(response.body());
                return new GameProfile(AuthUtils.parseMojangUuid(json.getString("id")), json.getString("name"));
            } catch (IOException | InterruptedException | JsonParserException ex) {
                throw new AuthenticationException("Profile request to Mojang failed", ex);
            }
        });
    }

    public CompletableFuture<Void> sendJoin(MojangToken token, GameProfile profile, String serverHash) {
        return CompletableFuture.runAsync(() -> {
            JsonObject reqJson = JsonObject.builder()
                    .value("accessToken", token.getValue())
                    .value("selectedProfile", AuthUtils.minifyUuid(profile.uuid()))
                    .value("serverId", serverHash)
                    .done();

           HttpRequest request = HttpRequest.newBuilder()
                   .uri(SESSION_JOIN_URI)
                   .POST(BodyPublishers.ofString(JsonWriter.string(reqJson)))
                   .build();

           try {
               httpClient.send(request, BodyHandlers.discarding());
           } catch (IOException | InterruptedException ex) {
               throw new AuthenticationException("Session join request to Mojang failed", ex);
           }
        });
    }

    public record GameProfile(UUID uuid, String username) {}

    public static MojangAuthenticator createDefault() {
        return new Builder().build();
    }

    public static Builder createBuilder() {
        return new Builder();
    }

    public static class Builder {

        private HttpClient httpClient;

        public Builder setHttpClient(HttpClient httpClient) {
            this.httpClient = Objects.requireNonNull(httpClient, "httpClient cannot be null");
            return this;
        }

        public MojangAuthenticator build() {
            if(httpClient == null)
                this.httpClient = HttpClient.newHttpClient();
            return new MojangAuthenticator(httpClient);
        }

    }

}
