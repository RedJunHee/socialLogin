package dongwoongkim.jwttutorial.repository;

import dongwoongkim.jwttutorial.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import javax.swing.text.html.Option;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    User findByUsername(String username);
    Optional<User> findByUsernameAndEmail(String username, String email);

    Optional<User> findByProviderAndProviderId(String provider, String providerId);
}
