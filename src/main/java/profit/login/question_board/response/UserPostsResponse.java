package profit.login.question_board.response;
import lombok.Builder;
import lombok.Data;
import profit.login.question_board.Entity.Board;

import java.util.List;

@Data
@Builder
public class UserPostsResponse {
    private String message;
    private List<Board> boards;
//    private List<BoardDto> boards;  // BoardDto 리스트로 변경

}
