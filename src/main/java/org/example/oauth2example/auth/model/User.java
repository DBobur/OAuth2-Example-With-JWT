package org.example.oauth2example.auth.model;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "users")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String name;
    private String email;
    private String password; // Register uchun
    private String provider; // GOOGLE, FACEBOOK, LOCAL
    private String picture;
    private String role; // USER, ADMIN va h.k.
}
