package com.example.api;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class UserController {

    // Hardcoded database credentials
    private static final String DB_URL = "jdbc:mysql://localhost:3306/myapp";
    private static final String DB_USER = "root";
    private static final String DB_PASSWORD = "admin123";

    // SQL Injection vulnerability - Statement with string concatenation
    @GetMapping("/users/{id}")
    public String getUser(@PathVariable String id) {
        try {
            Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
            Statement stmt = conn.createStatement();

            // VULNERABLE: Direct string concatenation in SQL
            String query = "SELECT * FROM users WHERE id = " + id;
            ResultSet rs = stmt.executeQuery(query);

            if (rs.next()) {
                return "User: " + rs.getString("name");
            }

            conn.close();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return "User not found";
    }

    // SQL Injection with String.format
    @GetMapping("/search")
    public String searchUsers(@RequestParam String name) {
        try {
            Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
            Statement stmt = conn.createStatement();

            // VULNERABLE: String.format in SQL query
            String query = String.format("SELECT * FROM users WHERE name LIKE '%%%s%%'", name);
            ResultSet rs = stmt.executeQuery(query);

            StringBuilder result = new StringBuilder();
            while (rs.next()) {
                result.append(rs.getString("name")).append(", ");
            }

            conn.close();
            return result.toString();
        } catch (Exception e) {
            e.printStackTrace();
            return "Error: " + e.getMessage();
        }
    }

    // XSS vulnerability - unescaped output
    @GetMapping("/profile")
    public String getProfile(@RequestParam String username) {
        // VULNERABLE: Directly embedding user input in HTML response
        return "<html><body><h1>Profile for: " + username + "</h1></body></html>";
    }
}
