package authorization.authorization;

import org.springframework.stereotype.Service;
@Service
public class userRegistration {

    private userauthrepo userRepo;
    private authrolerepo roleRepo;

    public userRegistration(userauthrepo userRepo, authrolerepo roleRepo) {
        this.userRepo = userRepo;
        this.roleRepo = roleRepo;
    }

    public authuser registerUser(String username, String password, String roleName) {
        authrole role = roleRepo.findByName(roleName);
        if (role == null) {
            role = new authrole();
            role.setName(roleName);
            roleRepo.save(role);
        }

        authuser user = new authuser();
        user.setUsername(username);
        user.setPassword(new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder().encode(password));
        user.getRole().add(role);
        return userRepo.save(user);
    }
    
}
