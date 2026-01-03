package com.example.service;

import java.io.*;
import java.security.MessageDigest;

public class AuthService {

    // Hardcoded API key
    private static final String API_KEY = "sk-prod-1234567890abcdef";

    // Weak cryptographic hash
    public static String hashPassword(String password) {
        try {
            // VULNERABLE: Using MD5 for password hashing
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hash = md.digest(password.getBytes());

            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                hexString.append(String.format("%02x", b));
            }

            return hexString.toString();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // Insecure deserialization
    public static Object deserializeUserSession(byte[] data) {
        try {
            // VULNERABLE: Deserializing untrusted data
            ByteArrayInputStream bis = new ByteArrayInputStream(data);
            ObjectInputStream ois = new ObjectInputStream(bis);
            return ois.readObject();
        } catch (Exception e) {
            throw new RuntimeException("Deserialization failed", e);
        }
    }

    // SQL Injection in authentication
    public static boolean authenticate(String username, String password) {
        try {
            Connection conn = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/auth",
                "root",
                "password123"
            );

            Statement stmt = conn.createStatement();
            String passwordHash = hashPassword(password);

            // VULNERABLE: String concatenation in SQL
            String query = "SELECT * FROM users WHERE username = '" + username +
                          "' AND password_hash = '" + passwordHash + "'";

            ResultSet rs = stmt.executeQuery(query);
            boolean authenticated = rs.next();

            conn.close();
            return authenticated;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }
}
