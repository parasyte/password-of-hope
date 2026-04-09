# The Password of Hope

A password decoder and generator for the classic GameBoy RPG, The Sword of Hope.

The source code includes a full description (to the best of my knowledge) of the internal password format.

The strongest password I've found online puts you at level 28 without the full inventory. This tool allows generating passwords for levels up to 32, put anything in your inventory, and choose which events have been completed.

Most of the events are undocumented at the moment (labeled "unknown"). And the state input is naive, only accepting raw hexadecimal.

Most of the error handling was left out, so there are generally panics instead of nice error messages. I wasn't sure if I wanted to publish this. But since I don't think this work has been done before, it seems like something that might be interesting to a few people.

## Disassembly

Here are my annotated notes from the password input screen. I've omitted the code that I didn't look at or didn't need for understanding the password format.

<details><summary>Notes</summary>

```asm
encode_b32():
L00_2b4a:
    00_2b4a: PUSH AF
    00_2b4b: PUSH HL
    00_2b4c: PUSH BC
    00_2b4d: PUSH DE
    00_2b4e: AND  $01
    00_2b50: JR   Z, L00_2b5d
    00_2b52: LD   A, D
    00_2b53: AND  $07
    00_2b55: LD   C, A
    00_2b56: LD   B, $00
    00_2b58: LD   HL, $2b82                 ; Bit table: 0x80 0x40 0x20 0x10 0x08 0x04 0x02 0x01
    00_2b5b: ADD  HL, BC
    00_2b5c: LD   A, (HL)
L00_2b5d:
    00_2b5d: PUSH AF
    00_2b5e: LD   A, D
    00_2b5f: AND  $07
    00_2b61: LD   C, A
    00_2b62: LD   B, $00
    00_2b64: LD   HL, $2b8a                 ; Mask table: 0x7F 0xBF 0xDF 0xEF 0xF7 0xFB 0xFD 0xFE
    00_2b67: ADD  HL, BC
    00_2b68: LD   A, (HL)
    00_2b69: LD   E, A
    00_2b6a: LD   C, D
    00_2b6b: SRL  C
    00_2b6d: SRL  C
    00_2b6f: SRL  C
    00_2b71: LD   B, $00
    00_2b73: LD   HL, $c760                 ; Encoded output
    00_2b76: ADD  HL, BC
    00_2b77: LD   A, (HL)
    00_2b78: AND  E
    00_2b79: LD   E, A
    00_2b7a: POP  AF
    00_2b7b: OR   E
    00_2b7c: LD   (HL), A
    00_2b7d: POP  DE
    00_2b7e: POP  BC
    00_2b7f: POP  HL
    00_2b80: POP  AF
    00_2b81: RET

checksum():
L00_2cbb:
    00_2cbb: LD   HL, $c761                 ; Second decoded byte
    00_2cbe: LD   B, $01
    00_2cc0: LD   C, $00
L00_2cc2:
    00_2cc2: LD   A, (HL+)
    00_2cc3: ADD  A, C
    00_2cc4: LD   C, A                      ; C += decoded[i];
    00_2cc5: INC  B                         ; i++;
    00_2cc6: LD   A, B
    00_2cc7: CP   $0a
    00_2cc9: JR   NZ, L00_2cc2
    00_2ccb: RET

; ...

    00_2e7b: LD   A, ($c800)                ; Read first password character
    00_2e7e: LD   D, $00                    ; bit index
    00_2e80: LD   E, $05                    ; bit count
    00_2e82: CALL L00_2afb                  ; encode_b32()
    00_2e85: LD   BC, $c801                 ; Second password character
    00_2e88: LD   HL, $2ccc                 ; Base32 encoding/obfuscation rules
                                            ;
                                            ;  ,---------- D: bit index
                                            ;  |  ,------- `diff` - obfuscates the input character
                                            ;  |  |  ,---- Unknown (ignored?) screen coordinates?
                                            ;  |  |  |
                                            ; 05 05 06
                                            ; 0A 10 07
                                            ; 0F 07 08
                                            ; 14 08 0A
                                            ; 19 06 0B
                                            ; 1E 14 0C
                                            ; 23 09 0D
                                            ; 28 13 14
                                            ; 2D 07 15
                                            ; 32 11 16
                                            ; 37 0A 17
                                            ; 3C 03 19
                                            ; 41 16 1A
                                            ; 46 08 1B
                                            ; 4B 15 1C
                                            ;
                                            ; FF
                                            ;  |
                                            ;  `---------- End of rules
L00_2e8b:
    00_2e8b: LD   A, (HL+)
    00_2e8c: CP   $ff
    00_2e8e: JR   Z, L00_2ea7
    00_2e90: LD   D, A                      ; bit index
    00_2e91: LD   A, (HL+)
    00_2e92: LD   E, A
    00_2e93: LD   A, (BC)                   ; Read next password character
    00_2e94: SUB  E
    00_2e95: PUSH AF
    00_2e96: LD   A, ($c800)                ; Read first password character
    00_2e99: LD   E, A
    00_2e9a: POP  AF
    00_2e9b: SUB  E
    00_2e9c: AND  $1f                       ; A = (pass[i] - diff - pass[0]) & 0x1f;
    00_2e9e: LD   E, $05                    ; bit count
    00_2ea0: CALL L00_2afb                  ; encode_b32()
    00_2ea3: INC  HL
    00_2ea4: INC  BC                        ; i++;
    00_2ea5: JR   L00_2e8b
L00_2ea7:
    00_2ea7: CALL L00_2cbb                  ; C = checksum()
    00_2eaa: LD   A, ($c760)                ; Read first decoded byte
    00_2ead: CP   C
    00_2eae: JR   Z, L00_2eb8
    00_2eb0: LD   A, $65
    00_2eb2: CALL L00_1447
    00_2eb5: JP   L00_2d41
L00_2eb8:
    00_2eb8: RET

; ...
```

</details>
