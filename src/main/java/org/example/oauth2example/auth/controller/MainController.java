package org.example.oauth2example.auth.controller;

import lombok.RequiredArgsConstructor;
import org.example.oauth2example.auth.config.JwtTokenUtil;
import org.example.oauth2example.auth.model.User;
import org.example.oauth2example.auth.service.UserService;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@Controller
@RequiredArgsConstructor
public class MainController {

    private final UserService userService;
    private final JwtTokenUtil jwtService;

    // ✅ Home Page (himoyalangan)
    @GetMapping("/home")
    public String homePage(@AuthenticationPrincipal OAuth2User principal, Model model) {
        if (principal == null) {
            return "redirect:/custom-login";
        }

        String name = principal.getAttribute("name");
        String email = principal.getAttribute("email");
        String picture = principal.getAttribute("picture");
        String provider = principal.getAuthorities().stream()
                .filter(a -> a.getAuthority().startsWith("ROLE_OAUTH2_"))
                .map(a -> a.getAuthority().replace("ROLE_OAUTH2_", ""))
                .findFirst()
                .orElse("UNKNOWN");

        // Facebook uchun rasm olish
        if ("FACEBOOK".equalsIgnoreCase(provider)) {
            Map<String, Object> pictureObj = principal.getAttribute("picture");
            if (pictureObj != null && pictureObj.get("data") instanceof Map<?, ?> data) {
                picture = (String) data.get("url");
            }
        }

        // DB saqlash (agar yo'q bo'lsa)
        String finalPicture = picture;
        User user = userService.findByEmail(email).orElseGet(() -> {
            User newUser = User.builder()
                    .name(name)
                    .email(email)
                    .provider(provider)
                    .picture(finalPicture)
                    .role("USER")
                    .build();
            return userService.saveOauth2User(newUser);
        });

        // JWT yaratish
        String token = jwtService.generateToken(user.getEmail());

        // Modelga qo'shish
        model.addAttribute("name", user.getName());
        model.addAttribute("email", user.getEmail());
        model.addAttribute("picture", user.getPicture());
        model.addAttribute("provider", user.getProvider());
        model.addAttribute("token", token);

        return "home"; // home.html
    }

    // ✅ Login sahifasi
    @GetMapping("/custom-login")
    public String loginPage() {
        return "login"; // login.html
    }

    // ✅ Register sahifasi
    @GetMapping("/register")
    public String registerPage() {
        return "register"; // register.html
    }

    // ✅ Register qilish va login qilish (post)
    @PostMapping("/register")
    public String registerUser(@RequestParam String name,
                               @RequestParam String email,
                               @RequestParam String password,
                               Model model) {

        // Email mavjudligini tekshirish
        if (userService.findByEmail(email).isPresent()) {
            model.addAttribute("error", "User with this email already exists!");
            return "register"; // register.html
        }

        // Saqlash
        User newUser = User.builder()
                .name(name)
                .email(email)
                .password(password) // service ichida encode qilinadi
                .provider("LOCAL")
                .role("USER")
                .build();

        userService.saveUser(newUser);

        // JWT yaratish
        String token = jwtService.generateToken(newUser.getEmail());

        // Modelga ma'lumot
        model.addAttribute("name", newUser.getName());
        model.addAttribute("email", newUser.getEmail());
        model.addAttribute("token", token);
        model.addAttribute("message", "Registered successfully and logged in!");

        return "home"; // home.html
    }
}
