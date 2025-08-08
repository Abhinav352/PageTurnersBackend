package com.example.PageTurners.services;

import com.example.PageTurners.models.AppUser;
import com.example.PageTurners.models.AuthRequest;
import com.example.PageTurners.models.RefreshTokenResponse;
import com.example.PageTurners.repository.AppUserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@Service
public class AuthService {

    @Autowired
    private AppUserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private KeycloakAdminService keycloakAdminService;

    @Autowired
    private KeyCloakService keycloakService;

    private final RestTemplate restTemplate = new RestTemplate();

    // Discord App Credentials
    @Value("${discord.client-id}")
    private String discordClientId;

    @Value("${discord.client-secret}")
    private String discordClientSecret;

    @Value("${discord.redirect-uri}")
    private String discordRedirectUri;

    // Google App Credentials
    @Value("${google.client-id}")
    private String googleClientId;

    @Value("${google.client-secret}")
    private String googleClientSecret;

    /**
     * Handles signup for local and OAuth providers
     */
    public AppUser signup(AuthRequest request) {
        String provider = request.getAuthProvider().toLowerCase();

        if ("local".equals(provider)) {
            keycloakAdminService.createUserInKeycloak(request.getUserName(), request.getPassword(), request.getProfile().getEmail());
            if (userRepository.findByUserName(request.getUserName()).isPresent()) {
                throw new RuntimeException("Username already exists");
            }

            AppUser user = new AppUser();
            user.setUserName(request.getUserName());
            user.setEmail(request.getProfile().getEmail());
            user.setDisplayName(request.getProfile().getDisplayName());
            user.setAvatarUrl(request.getProfile().getAvatarUrl());
            user.setProvider("local");
            user.setTimeZone(request.getTimeZone());
            user.setLatitude(request.getLocation().getLatitude());
            user.setLongitude(request.getLocation().getLongitude());
            user.setPassword(passwordEncoder.encode(request.getPassword()));

            return userRepository.save(user);
        }

        // OAuth signup
        Map<String, Object> userInfo = fetchOAuthProfile(request.getOauthToken(), provider);
        String email = (String) userInfo.get("email");

        if (userRepository.findByEmailAndProvider(email, provider).isPresent()) {
            throw new RuntimeException("OAuth user already exists");
        }

        AppUser user = new AppUser();
        user.setUserName(request.getUserName());
        user.setEmail(email);
        user.setDisplayName((String) userInfo.get("displayName"));
        user.setAvatarUrl((String) userInfo.get("avatarUrl"));
        user.setProvider(provider);
        user.setTimeZone(request.getTimeZone());
        user.setLatitude(request.getLocation().getLatitude());
        user.setLongitude(request.getLocation().getLongitude());

        // Save tokens if provided
        user.setAccessToken((String) userInfo.get("accessToken"));
        user.setRefreshToken((String) userInfo.get("refreshToken"));
        if (userInfo.get("expiresIn") != null) {
            long expiryTime = System.currentTimeMillis() / 1000 + (Integer) userInfo.get("expiresIn");
            user.setTokenExpiry(expiryTime);
        }

        return userRepository.save(user);
    }

    /**
     * Handles login for local and OAuth providers
     * Auto-signup for OAuth users if first login
     */
    public AppUser login(AuthRequest request) {
        String provider = request.getAuthProvider().toLowerCase();

        if ("local".equalsIgnoreCase(request.getAuthProvider())) {
            AppUser user = userRepository.findByUserName(request.getUserName())
                    .orElseThrow(() -> new RuntimeException("User not found"));

            if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
                throw new RuntimeException("Invalid credentials");
            }

            Map<String, Object> tokenData = keycloakService.generateToken(request.getUserName(), request.getPassword());
            user.setAccessToken((String) tokenData.get("access_token"));
            user.setRefreshToken((String) tokenData.get("refresh_token"));
            Integer expiresIn = (Integer) tokenData.get("expires_in");
            if (expiresIn != null) {
                user.setTokenExpiry(System.currentTimeMillis() / 1000 + expiresIn);
            }
            return userRepository.save(user);
        }

        // OAuth login
        Map<String, Object> userInfo = fetchOAuthProfile(request.getOauthToken(), provider);
        String email = (String) userInfo.get("email");

        return userRepository.findByEmailAndProvider(email, provider)
                .orElseGet(() -> {
                    // Auto-create user on first OAuth login
                    AppUser user = new AppUser();
                    user.setUserName(request.getUserName());
                    user.setEmail(email);
                    user.setDisplayName((String) userInfo.get("displayName"));
                    user.setAvatarUrl((String) userInfo.get("avatarUrl"));
                    user.setProvider(provider);
                    user.setTimeZone(request.getTimeZone());
                    user.setLatitude(request.getLocation().getLatitude());
                    user.setLongitude(request.getLocation().getLongitude());

                    // Save tokens
                    user.setAccessToken((String) userInfo.get("accessToken"));
                    user.setRefreshToken((String) userInfo.get("refreshToken"));
                    if (userInfo.get("expiresIn") != null) {
                        long expiryTime = System.currentTimeMillis() / 1000 + (Integer) userInfo.get("expiresIn");
                        user.setTokenExpiry(expiryTime);
                    }

                    return userRepository.save(user);
                });
    }

    /**
     * Refresh token for a specific user and return detailed token info
     */
    public RefreshTokenResponse refreshUserToken(Long userId) {
        AppUser user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (user.getRefreshToken() == null) {
            throw new RuntimeException("No refresh token stored for this user");
        }

        Map<String, Object> newTokens = refreshOAuthToken(user.getProvider(), user.getRefreshToken());

        String newAccessToken = (String) newTokens.get("access_token");
        String newRefreshToken = (String) newTokens.get("refresh_token"); // Discord rotates refresh tokens
        Integer expiresIn = (Integer) newTokens.get("expires_in");

        user.setAccessToken(newAccessToken);
        if (newRefreshToken != null) {
            user.setRefreshToken(newRefreshToken);
        }
        if (expiresIn != null) {
            long expiryTime = System.currentTimeMillis() / 1000 + expiresIn;
            user.setTokenExpiry(expiryTime);
        }

        userRepository.save(user);

        long currentEpoch = System.currentTimeMillis() / 1000;
        Long tokenExpiry = user.getTokenExpiry();
        Long expiresInCalculated = (tokenExpiry != null) ? tokenExpiry - currentEpoch : null;
        String expiresAt = (tokenExpiry != null)
                ? Instant.ofEpochSecond(tokenExpiry).toString()
                : null;

        return new RefreshTokenResponse(
                user.getAccessToken(),
                user.getRefreshToken(),
                tokenExpiry,
                expiresInCalculated,
                expiresAt
        );
    }

    /**
     * Generic OAuth profile fetcher
     */
    private Map<String, Object> fetchOAuthProfile(String tokenOrCode, String provider) {
        return switch (provider) {
            case "google" -> fetchGoogleProfile(tokenOrCode);
            case "discord" -> fetchDiscordProfile(tokenOrCode);
            default -> throw new RuntimeException("Unsupported auth provider: " + provider);
        };
    }

    /**
     * Google OAuth: supports access token and short code
     */
    private Map<String, Object> fetchGoogleProfile(String tokenOrCode) {
        String accessToken = tokenOrCode;
        String refreshToken = null;
        Integer expiresIn = null;

        try {
            // If tokenOrCode is short, treat as authorization code and exchange for token
            if (tokenOrCode.length() < 100) {
                HttpHeaders headers = new HttpHeaders();
                headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

                MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
                body.add("client_id", googleClientId);
                body.add("client_secret", googleClientSecret);
                body.add("grant_type", "authorization_code");
                body.add("code", tokenOrCode);
                body.add("redirect_uri", "http://localhost:8080/oauth/google");

                HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

                ResponseEntity<Map> tokenResponse = restTemplate.postForEntity(
                        "https://oauth2.googleapis.com/token",
                        request,
                        Map.class
                );

                Map<String, Object> tokenData = tokenResponse.getBody();
                if (tokenData == null || tokenData.get("access_token") == null) {
                    throw new RuntimeException("Failed to exchange Google code for access token");
                }

                accessToken = (String) tokenData.get("access_token");
                refreshToken = (String) tokenData.get("refresh_token");
                expiresIn = tokenData.get("expires_in") != null
                        ? ((Number) tokenData.get("expires_in")).intValue()
                        : null;
            }

            // Fetch user info using access token
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(accessToken);
            HttpEntity<Void> entity = new HttpEntity<>(headers);

            ResponseEntity<Map> response = restTemplate.exchange(
                    "https://www.googleapis.com/oauth2/v3/userinfo",
                    HttpMethod.GET,
                    entity,
                    Map.class
            );

            Map<String, Object> body = response.getBody();
            if (body == null || body.get("email") == null) {
                throw new RuntimeException("Failed to fetch Google user info.");
            }

            Map<String, Object> result = new HashMap<>();
            result.put("email", body.get("email"));
            result.put("displayName", body.get("name"));
            result.put("avatarUrl", body.get("picture"));
            result.put("accessToken", accessToken);
            result.put("refreshToken", refreshToken);
            result.put("expiresIn", expiresIn);
            return result;

        } catch (HttpClientErrorException ex) {
            throw new RuntimeException("Google token validation failed: "
                    + ex.getStatusCode() + " " + ex.getResponseBodyAsString());
        } catch (Exception e) {
            throw new RuntimeException("Unexpected error during Google profile fetch", e);
        }
    }

    /**
     * Discord OAuth: exchanges code for token if needed and fetches /users/@me
     */
    private Map<String, Object> fetchDiscordProfile(String tokenOrCode) {
        String accessToken = tokenOrCode;
        String refreshToken = null;
        Integer expiresIn = null;

        // If short code, exchange for token
        if (tokenOrCode.length() < 60) {
            Map<String, Object> tokenData = exchangeDiscordCodeForToken(tokenOrCode);
            accessToken = (String) tokenData.get("access_token");
            refreshToken = (String) tokenData.get("refresh_token");
            expiresIn = (Integer) tokenData.get("expires_in");
        }

        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + accessToken);
        HttpEntity<Void> entity = new HttpEntity<>(headers);

        ResponseEntity<Map> response = restTemplate.exchange(
                "https://discord.com/api/users/@me",
                HttpMethod.GET,
                entity,
                Map.class
        );

        Map<String, Object> userInfo = response.getBody();
        Map<String, Object> result = new HashMap<>();
        result.put("email", userInfo.get("email"));
        result.put("displayName", userInfo.get("username"));
        result.put("avatarUrl", "https://cdn.discordapp.com/avatars/"
                + userInfo.get("id") + "/" + userInfo.get("avatar") + ".png");
        result.put("accessToken", accessToken);
        result.put("refreshToken", refreshToken);
        result.put("expiresIn", expiresIn);
        return result;
    }

    /**
     * Exchange Discord authorization code for access + refresh token
     */
    private Map<String, Object> exchangeDiscordCodeForToken(String code) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("client_id", discordClientId);
        body.add("client_secret", discordClientSecret);
        body.add("grant_type", "authorization_code");
        body.add("code", code);
        body.add("redirect_uri", discordRedirectUri);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

        ResponseEntity<Map> response = restTemplate.postForEntity(
                "https://discord.com/api/oauth2/token",
                request,
                Map.class
        );

        return response.getBody();
    }

    /**
     * Generic token refresh logic
     */
    public Map<String, Object> refreshOAuthToken(String provider, String refreshToken) {
        return switch (provider.toLowerCase()) {
            case "google" -> refreshGoogleToken(refreshToken);
            case "discord" -> refreshDiscordToken(refreshToken);
            case "local" -> keycloakService.refreshToken(refreshToken);
            default -> throw new RuntimeException("Unsupported provider: " + provider);
        };
    }

    private Map<String, Object> refreshGoogleToken(String refreshToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("client_id", googleClientId);
        body.add("client_secret", googleClientSecret);
        body.add("grant_type", "refresh_token");
        body.add("refresh_token", refreshToken);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

        ResponseEntity<Map> response = restTemplate.postForEntity(
                "https://oauth2.googleapis.com/token",
                request,
                Map.class
        );

        return response.getBody();
    }

    private Map<String, Object> refreshDiscordToken(String refreshToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("client_id", discordClientId);
        body.add("client_secret", discordClientSecret);
        body.add("grant_type", "refresh_token");
        body.add("refresh_token", refreshToken);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

        ResponseEntity<Map> response = restTemplate.postForEntity(
                "https://discord.com/api/oauth2/token",
                request,
                Map.class
        );

        return response.getBody();
    }

    public String expireUserToken(Long userId) {
        AppUser user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        String provider = user.getProvider();
        String accessToken = user.getAccessToken();
        String refreshToken = user.getRefreshToken();

        try {
            if( "local".equalsIgnoreCase(provider)) {
                expireLocalToken(accessToken);
            }
            else if ("google".equalsIgnoreCase(provider)) {
                HttpHeaders headers = new HttpHeaders();
                headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

                // ✅ Only revoke refresh token
                if (refreshToken != null) {
                    MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
                    body.add("token", refreshToken);

                    restTemplate.postForEntity(
                            "https://oauth2.googleapis.com/revoke",
                            new HttpEntity<>(body, headers),
                            String.class
                    );
                }
            }
             else if ("discord".equalsIgnoreCase(provider)) {
                HttpHeaders headers = new HttpHeaders();
                headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

                // Revoke access token
                if (accessToken != null) {
                    MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
                    body.add("client_id", discordClientId);
                    body.add("client_secret", discordClientSecret);
                    body.add("token", accessToken);

                    restTemplate.postForEntity(
                            "https://discord.com/api/oauth2/token/revoke",
                            new HttpEntity<>(body, headers),
                            String.class
                    );
                }

                // Revoke refresh token
                if (refreshToken != null) {
                    MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
                    body.add("client_id", discordClientId);
                    body.add("client_secret", discordClientSecret);
                    body.add("token", refreshToken);

                    restTemplate.postForEntity(
                            "https://discord.com/api/oauth2/token/revoke",
                            new HttpEntity<>(body, headers),
                            String.class
                    );
                }
            }

            // ✅ Clear tokens from DB to fully log out the user
            user.setAccessToken(null);
            user.setRefreshToken(null);
            user.setTokenExpiry(null);
            userRepository.save(user);

            return "Access and refresh tokens expired successfully";

        } catch (Exception e) {
            throw new RuntimeException("Failed to expire token", e);
        }
    }

    public void expireLocalToken(String accessToken) {
        keycloakService.revokeToken(accessToken);
    }


}
