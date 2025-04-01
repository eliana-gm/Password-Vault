package com.example.passwordmanager.controller;

import com.example.passwordmanager.service.PasswordService;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.Set;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "http://localhost:3000") // Allow frontend dev server
public class PasswordController {

    private final PasswordService passwordService = new PasswordService();

    @PostMapping("/authenticate")
    public Map<String, Object> authenticate(@RequestBody Map<String, String> payload) {
        char[] passcode = payload.get("passcode").toCharArray();
        boolean success;
        try {
            success = passwordService.authenticate(passcode);
        } catch (Exception e) {
            return Map.of("success", false, "error", e.getMessage());
        }
        return Map.of("success", success);
    }

    @PostMapping("/passwords")
    public Map<String, Object> addPassword(@RequestBody Map<String, String> payload) {
        String label = payload.get("label");
        String password = payload.get("password");
        String passcode = payload.get("passcode");
    
        if (label == null || password == null || passcode == null) {
            return Map.of("success", false, "error", "Missing required fields");
        }
    
        try {
            passwordService.addPassword(label, password, passcode.toCharArray());
            return Map.of("success", true);
        } catch (Exception e) {
            return Map.of("success", false, "error", e.getMessage());
        }
    } 

    @GetMapping("/passwords/{label}")
    public Map<String, String> getPassword(@PathVariable String label) {
        String password = passwordService.getPassword(label);
        if (password != null) {
            return Map.of("password", password);
        } else {
            return Map.of("error", "Label not found");
        }
    }

    @GetMapping("/passwords")
    public Set<String> getAllLabels() {
        return passwordService.getLabels();
    }

    @DeleteMapping("/reset")
    public Map<String, Object> resetVault() {
        try {
            passwordService.resetVault();
            return Map.of("success", true);
        } catch (Exception e) {
            return Map.of("success", false, "error", e.getMessage());
        }
    }

}
