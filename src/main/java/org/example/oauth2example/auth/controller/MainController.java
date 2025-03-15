package org.example.oauth2example.auth.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.Map;

@Controller
public class MainController {

    @GetMapping("/custom-login")
    public String loginPage() {
        return "login";
    }

    @GetMapping("/home")
    public String homePage(Model model, @AuthenticationPrincipal OAuth2User principal) {
        if (principal != null) {
            String name = principal.getAttribute("name");
            String email = principal.getAttribute("email");
            String picture = null;

            String provider = principal.getAuthorities().stream()
                    .filter(a -> a.getAuthority().startsWith("ROLE_OAUTH2_"))
                    .map(a -> a.getAuthority().replace("ROLE_OAUTH2_", ""))
                    .findFirst()
                    .orElse("UNKNOWN");
            
            if ("FACEBOOK".equalsIgnoreCase(provider)) {
                // Facebook uchun picture obyekt sifatida keladi
                Map<String, Object> pictureObj = principal.getAttribute("picture");
                if (pictureObj != null) {
                    Map<String, Object> data = (Map<String, Object>) pictureObj.get("data");
                    if (data != null) {
                        picture = (String) data.get("url");
                    }
                }
            } else {
                // Google yoki boshqa provider'lar uchun
                //picture = principal.getAttribute("picture");
            }

            // Modelga ma'lumotlarni qo'shish
            model.addAttribute("name", name);
            model.addAttribute("email", email);
            model.addAttribute("picture", picture);
            model.addAttribute("provider", provider);
        } else {
            // Agar foydalanuvchi autentifikatsiya qilinmagan bo'lsa, login sahifasiga yo'naltirish
            return "redirect:/custom-login";
        }
        return "home"; // templates/home.html
    }

    // Main page
    @GetMapping("/")
    public String mainPage() {
        return "index"; // templates/index.html
    }
}