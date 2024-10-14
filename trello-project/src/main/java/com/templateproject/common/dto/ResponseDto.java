package com.templateproject.common.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class ResponseDto<T> {

    private int statusCode;
    private String message;
    private T data;


    private ResponseDto(HttpStatus status, String message, T data) {
        this.statusCode = status.value();
        this.message = message;
        this.data = data;
    }

    public static <T> ResponseEntity<ResponseDto<T>> toEntity(ResponseDto<T> responseDto) {
        return ResponseEntity.status(responseDto.statusCode).body(responseDto);
    }

    public ResponseEntity<ResponseDto<T>> toEntity(){
        return ResponseDto.toEntity(this);
    }

    public static <T> ResponseDto<T> of(HttpStatus status){
        return new ResponseDto<T>(status, null, null);
    }

    public static <T> ResponseDto<T> of(HttpStatus status, String message){
        return new ResponseDto<T>(status, message, null);
    }

    public static <T> ResponseDto<T> of(HttpStatus status, T body){
        return new ResponseDto<T>(status, null, body);
    }

    public static <T> ResponseDto<T> of(HttpStatus status, String message, T body){
        return new ResponseDto<T>(status, message, body);
    }
}
