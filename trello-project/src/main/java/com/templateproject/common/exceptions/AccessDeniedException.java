package com.templateproject.common.exceptions;

/**
 * 사용자가 인증되었으나 접근 권한이 없을 때 사용합니다.
 * ex) 다른 사람의 게시글을 삭제하거나, 어드민 페이지에 접근하거나
 */
public class AccessDeniedException extends RuntimeException{
    public AccessDeniedException(String message) {
        super(message);
    }

    public AccessDeniedException() {
        super("접근 권한이 없습니다.");
    }
}
