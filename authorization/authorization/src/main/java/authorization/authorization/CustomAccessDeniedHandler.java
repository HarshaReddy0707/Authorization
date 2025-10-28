package authorization.authorization;

import java.io.IOException;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Component;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
@Component
public class CustomAccessDeniedHandler implements org.springframework.security.web.access.AccessDeniedHandler {

    

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
            AccessDeniedException accessDeniedException) throws IOException, ServletException {
        System.out.println("⚠ CSRF or Access Denied Error: " + accessDeniedException.getMessage());

        // Redirect to a custom error page
        response.sendRedirect("/access-denied");
    }
    
}