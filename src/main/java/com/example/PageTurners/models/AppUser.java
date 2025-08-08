package com.example.PageTurners.models;

import jakarta.persistence.*;
import lombok.Data;

    @Entity
    @Data
    public class AppUser {
        @Id
        @GeneratedValue(strategy = GenerationType.IDENTITY)
        private Long id;

        private String userName;
        private String email;
        private String password; // Only for local users (hashed)
        private String provider; // local/google/discord
        private String avatarUrl;
        private String displayName;
        private String timeZone;
        private Double latitude;
        private Double longitude;

        @Column(length = 2048)
        private String accessToken;
        @Column(length = 2048)
        private String refreshToken;
        private Long tokenExpiry;

    }
