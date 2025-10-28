package authorization.authorization;

import org.springframework.stereotype.Repository;

@Repository
public interface authrolerepo extends org.springframework.data.jpa.repository.JpaRepository<authrole,Long> {
    authrole findByName(String name);
    
}
