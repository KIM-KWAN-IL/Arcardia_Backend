package profit.login.repository;

import org.springframework.data.repository.CrudRepository;
import profit.login.dto.TokenRedis;

import java.util.Optional;
public interface TokenRedisRepository extends CrudRepository<TokenRedis, String> {

    Optional<TokenRedis> findByAccessToken(String accessToken); // AccessToken으로 찾아내기
}
