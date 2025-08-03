package com.example.PageTurners.models;

import lombok.Data;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class RefreshTokenResponse {
    private String accessToken;
    private String refreshToken;
    private Long tokenExpiry;  // epoch seconds
    private Long expiresIn;    // seconds left
    private String expiresAt;  // human-readable UTC
}