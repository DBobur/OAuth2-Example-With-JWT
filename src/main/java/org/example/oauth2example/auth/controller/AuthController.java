package org.example.oauth2example.auth.controller;


import lombok.RequiredArgsConstructor;
import org.example.oauth2example.auth.config.JwtTokenUtil;
import org.example.oauth2example.auth.model.User;
import org.example.oauth2example.auth.repository.UserRepository;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final JwtTokenUtil jwtUtils;
    private final UserRepository userRepository;


    @GetMapping("/oauth2/success")
    public String getToken(OAuth2User principal) {
        String email = principal.getAttribute("email");
        Optional<User> user = userRepository.findByEmail(email);

        if (user.isPresent()) {
            return jwtUtils.generateToken(email);
        }
        return "User not found";
    }
}
