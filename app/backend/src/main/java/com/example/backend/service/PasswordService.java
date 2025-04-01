package com.example.passwordmanager.service;

import com.example.passwordmanager.util.CryptoUtils;

import javax.crypto.SecretKey;
import java.io.*;
import java.util.*;

public class PasswordService {
    private static final String FILE_NAME = "passwords.txt";
    private final Map<String, String> passwordMap = new HashMap<>();
    private byte[] salt;
    private SecretKey secretKey;

    public boolean authenticate(char[] passcode) throws IOException {
        File file = new File(FILE_NAME);
        if (!file.exists()) {
            this.salt = CryptoUtils.generateSalt();
            this.secretKey = CryptoUtils.getSecretKey(passcode, salt);
            try (BufferedWriter writer = new BufferedWriter(new FileWriter(file))) {
                String token = CryptoUtils.encrypt("VALID_TOKEN", secretKey);
                String encodedSalt = Base64.getEncoder().encodeToString(salt);
                writer.write(encodedSalt + ":" + token);
                writer.newLine();
            }
            return true;
        }
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String firstLine = reader.readLine();
            if (firstLine != null && firstLine.contains(":")) {
                String[] parts = firstLine.split(":");
                this.salt = Base64.getDecoder().decode(parts[0]);
                this.secretKey = CryptoUtils.getSecretKey(passcode, salt);
                String decryptedToken = CryptoUtils.decrypt(parts[1], secretKey);
                if (!"VALID_TOKEN".equals(decryptedToken)) return false;
            }
            loadPasswords(reader);
        }
        return true;
    }

    private void loadPasswords(BufferedReader reader) throws IOException {
        String line;
        while ((line = reader.readLine()) != null) {
            String[] parts = line.split(":");
            if (parts.length == 2) {
                passwordMap.put(parts[0], parts[1]);
            }
        }
    }

    public void addPassword(String label, String password, char[] passcode) {
        if (label == null || password == null || passcode == null) {
            throw new IllegalArgumentException("Label, password, and passcode must not be null");
        }
    
        // Re-derive secret key for each session based on passcode + salt
        this.secretKey = CryptoUtils.getSecretKey(passcode, this.salt);
    
        String encrypted = CryptoUtils.encrypt(password, secretKey);
        passwordMap.put(label, encrypted);
        saveToFile();
    }
    

    public String getPassword(String label) {
        String encrypted = passwordMap.get(label);
        return encrypted != null ? CryptoUtils.decrypt(encrypted, secretKey) : null;
    }

    public Set<String> getLabels() {
        return passwordMap.keySet();
    }

    private void saveToFile() {
        try {
            List<String> lines = new ArrayList<>();
            lines.add(Base64.getEncoder().encodeToString(salt) + ":" + CryptoUtils.encrypt("VALID_TOKEN", secretKey));
            for (var entry : passwordMap.entrySet()) {
                lines.add(entry.getKey() + ":" + entry.getValue());
            }
            try (BufferedWriter writer = new BufferedWriter(new FileWriter(FILE_NAME))) {
                for (String line : lines) {
                    writer.write(line);
                    writer.newLine();
                }
            }
        } catch (IOException e) {
            throw new RuntimeException("Failed to save file: " + e.getMessage());
        }
    }

    public void resetVault() {
        File file = new File(FILE_NAME);
        if (file.exists()) {
            file.delete();
        }
        passwordMap.clear();
        salt = null;
        secretKey = null;
    }    

}