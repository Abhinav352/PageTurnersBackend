package com.example.PageTurners.models;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
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
    }
