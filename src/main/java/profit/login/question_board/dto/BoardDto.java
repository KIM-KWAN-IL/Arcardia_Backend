package profit.login.question_board.dto;

import lombok.Builder;
import lombok.Data;
import org.springframework.web.multipart.MultipartFile;
import profit.login.question_board.Entity.Board;
import profit.login.question_board.Entity.UploadImage;

import java.time.LocalDateTime;

@Data
@Builder
public class BoardDto {

    private Long id;
    private String userLoginId;
    private String userNickname;
    private String title;
    private String body;
    private Integer likeCnt;
    private Integer viewCount;
    private LocalDateTime createdAt;
    private LocalDateTime lastModifiedAt;
    private MultipartFile newImage;
    private UploadImage uploadImage;

    public static BoardDto of(Board board) {
        return BoardDto.builder()
                .id(board.getId())
                .userLoginId(board.getUser().getEmail())
                .userNickname(board.getUser().getNickname())
                .title(board.getTitle())
                .body(board.getBody())
                .viewCount(board.getViewCount())
                .createdAt(board.getCreatedAt())
                .lastModifiedAt(board.getLastModifiedAt())
                .likeCnt(board.getLikes().size())
                .uploadImage(board.getUploadImage())
                .build();
    }
}