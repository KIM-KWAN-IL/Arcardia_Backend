package profit.login.question_board.response;


import lombok.Builder;
import lombok.Data;
import profit.login.entity.UserRole;

@Data
@Builder
public class ReplyWriteResponse {
    private String message;
    private String nextUrl;
    private String isExpert;
    private UserRole userRole;
    private String nickName;
}