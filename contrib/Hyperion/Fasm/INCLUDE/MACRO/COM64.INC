
; Macroinstructions for interfacing the COM (Component Object Model) classes

macro cominvk object,proc,[arg]
 { common
    assert defined object#.com.object ; must be a COM object
    macro call dummy
    \{ mov rax,[object]
       mov rax,[rax]
       call [rax+object#.#proc] \}
    fastcall ,[object],arg
    purge call }

macro comcall handle,interface,proc,[arg]
 { common
    assert defined interface#.com.interface ; must be a COM interface
    macro call dummy
    \{ if handle eqtype rax | handle eqtype 0
	local ..handle
	label ..handle at handle
	mov rax,[..handle]
       else
	mov rax,handle
	mov rax,[rax]
       end if
       call [rax+interface#.#proc] \}
    fastcall ,handle,arg
    purge call }

macro interface name,[proc]
 { common
    struc name \{
    match , @struct \\{ define field@struct .,name, \\}
    match no, @struct \\{ . dq ?
    virtual at 0
   forward
    .#proc dq ?
   common
    .\#\\.com.object = name#.com.interface
    end virtual \\} \}
    virtual at 0
   forward
     name#.#proc dq ?
   common
     name#.com.interface = $ shr 3
    end virtual }

