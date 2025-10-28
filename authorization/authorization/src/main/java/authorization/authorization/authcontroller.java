package authorization.authorization;


import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

import java.util.Set;

import org.springframework.security.core.Authentication;


@Controller
public class authcontroller {
    

    private userRegistration userReg;
    public authcontroller(userRegistration userReg) {
        this.userReg = userReg;
    }

@GetMapping("/login")
public String login() {
    return "login";
}



    
@GetMapping("/register")
public String register(Model model) {
    
    model.addAttribute("entity", new authuser());
    return "register";      
}

@PostMapping("/save")
public String Registration(@ModelAttribute("entity") authuser entity) {
    System.out.println("eneteered");
    userReg.registerUser(entity.getUsername(), entity.getPassword(), "ROLE_ADMIN");
    System.out.println("registered");
    // persist or process the entity here, then redirect or return a view
    return "redirect:/login";
}

 @GetMapping("/default")
    public String defaultAfterLogin(Authentication authentication) {
        
        // Get roles for logged-in user
        Set<String> roles = AuthorityUtils.authorityListToSet(authentication.getAuthorities());

        if (roles.contains("ROLE_ADMIN")) {
            return "redirect:/admin/home";
        }
        if (roles.contains("ROLE_USER")) {
            return "redirect:/user/home";
        }

        return "redirect:/login?error=true"; // fallback
    }


     @GetMapping("/admin/home")
    public String adminHome() {
        return "adminhome";  // admin_home.html in templates
    }

    @GetMapping("/user/home")
    public String userHome() {
        return "userhome";   // user_home.html in templates
    }

    @GetMapping("/access-denied")
    public String accessDenied() {
        return "access-denied";
    }

}
