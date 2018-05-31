option casemap :none

_TEXT    SEGMENT
    ;https://msdn.microsoft.com/en-us/library/windows/hardware/ff561499(v=vs.85).aspx
    ;misc
    EXTERN evalIngress:                                    qword

    PUBLIC evalIngressFnc
    evalIngressFnc PROC
        mov     r9, rax
        jmp evalIngress;
    evalIngressFnc ENDP




_TEXT    ENDS
END
