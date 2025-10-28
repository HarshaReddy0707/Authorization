package authorization.authorization;

import org.springframework.stereotype.Repository;

@Repository
public interface userauthrepo extends org.springframework.data.jpa.repository.JpaRepository<authuser,Long> {
    authuser findByUsername(String username);
    
}
