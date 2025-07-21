package com.example.PageTurners.models;

import lombok.Data;

@Data
public class AuthRequest {
    private String userName;
    private String password;
    private String timeZone;
    private String authProvider;
    private String oauthToken;
    private Profile profile;
    private Location location;
}
