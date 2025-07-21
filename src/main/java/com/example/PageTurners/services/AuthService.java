package com.example.PageTurners.services;

import com.example.PageTurners.repository.AppUserRepository;
import com.example.PageTurners.models.AppUser;
import com.example.PageTurners.models.AuthRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

@Service
public class AuthService {

    @Autowired
    private AppUserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public AppUser signup(AuthRequest request) {
        String provider = request.getAuthProvider().toLowerCase();

        if ("local".equals(provider)) {
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
        Map<String, Object> userInfo = fetchProfileFromOAuth(request.getOauthToken(), provider);
        String email = (String) userInfo.get("email");

        if (userRepository.findByEmailAndProvider(email, provider).isPresent()) {
            throw new RuntimeException("User already exists");
        }

        AppUser user = new AppUser();
        user.setUserName(request.getUserName());
        user.setEmail(email);
        user.setProvider(provider);
        user.setAvatarUrl((String) userInfo.get("avatarUrl"));
        user.setDisplayName((String) userInfo.get("displayName"));
        user.setTimeZone(request.getTimeZone());
        user.setLatitude(request.getLocation().getLatitude());
        user.setLongitude(request.getLocation().getLongitude());
        return userRepository.save(user);
    }

    public AppUser login(AuthRequest request) {
        String provider = request.getAuthProvider().toLowerCase();

        if ("local".equals(provider)) {
            AppUser user = userRepository.findByUserName(request.getUserName())
                    .orElseThrow(() -> new RuntimeException("User not found"));

            if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
                throw new RuntimeException("Invalid credentials");
            }

            return user;
        }

        // OAuth login
        Map<String, Object> userInfo = fetchProfileFromOAuth(request.getOauthToken(), provider);
        String email = (String) userInfo.get("email");

        return userRepository.findByEmailAndProvider(email, provider)
                .orElseThrow(() -> new RuntimeException("OAuth user not found"));
    }

    private Map<String, Object> fetchProfileFromOAuth(String token, String provider) {
        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        HttpEntity<Void> entity = new HttpEntity<>(headers);

        String url = switch (provider) {
            case "google" -> "https://www.googleapis.com/oauth2/v3/userinfo";
            case "discord" -> "https://discord.com/api/users/@me";
            default -> throw new RuntimeException("Unsupported provider");
        };

        ResponseEntity<Map> response = restTemplate.exchange(url, HttpMethod.GET, entity, Map.class);
        Map<String, Object> userInfo = response.getBody();

        return Map.of(
                "email", userInfo.get("email"),
                "displayName", userInfo.getOrDefault("name", userInfo.get("username")),
                "avatarUrl", provider.equals("discord") ?
                        "https://cdn.discordapp.com/avatars/" + userInfo.get("id") + "/" + userInfo.get("avatar") + ".png"
                        : userInfo.get("picture")
        );
    }
}

