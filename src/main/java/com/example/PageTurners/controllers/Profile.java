package com.example.PageTurners.controllers;

import com.example.PageTurners.models.RefreshTokenResponse;
import com.example.PageTurners.services.AuthService;
import com.example.PageTurners.models.AppUser;
import com.example.PageTurners.models.AuthRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class Profile {

    @Autowired
    private AuthService authService;

    @PostMapping("/signup")
    public ResponseEntity<?> signup(@RequestBody AuthRequest request) {
        try {
            AppUser user = authService.signup(request);
            return ResponseEntity.ok(user);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AuthRequest request) {
        try {
            AppUser user = authService.login(request);
            return ResponseEntity.ok(user);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }
    @PostMapping("/refresh-user-token")
    public ResponseEntity<RefreshTokenResponse> refreshUserToken(@RequestBody Long userId) {
        RefreshTokenResponse updatedUser = authService.refreshUserToken(userId);
        return ResponseEntity.ok(updatedUser);
    }
}
