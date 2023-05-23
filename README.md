# Malleable-CS-Profiles
A list of python tools to help create an OPSEC-safe Cobalt Strike profile. This is the Github repository of the relevant blog post: [Unleashing the Unseen: Harnessing the Power of Cobalt Strike Profiles for EDR Evasion](https://whiteknightlabs.com/2023/05/23/unleashing-the-unseen-harnessing-the-power-of-cobalt-strike-profiles-for-edr-evasion/)

## Usage  

### prepend.py  
Is a python script which generates dynamic junk shellcode which will be appended on the beginning of the actual shellcode. To use the script, execute:  
```bash
python3 prepend.py
```

Copy the output and paste it in the profile (inside transform-x64 or transform-x86 block). The profile will look like the following:  
```
transform-x64 {
    ...
    prepend "\x44\x40\x4B\x43\x4C\x48\x90\x66\x90\x0F\x1F\x00\x66\x0F\x1F\x04\x00\x0F\x1F\x04\x00\x0F\x1F\x00\x0F\x1F\x00";
    ...
}
```

### rich_header.py  
Is a python script which generates dynamic shellcode that is responsible for the meta-information inserted by the compiler. The Rich header is a PE section that serves as a fingerprint of a Windows' executable’s build environment. To use the script, execute:  
```bash
python3 rich_header.py
```

Copy the output and paste it in the profile (inside transform-x64 or transform-x86 block). The profile will look like the following:  
```
stage {
    ...
    set rich_header "\x2e\x9a\xad\xf1...";
    ...
}
```

### rule_f0b627fc_bypass.py  
Is a python script which modifies the shellcode in order bypass rule `Windows_Trojan_CobaltStrike_f0b627fc` from Elastic. To use the script, execute:  
```bash
python3 rule_f0b627fc_bypass.py  beacon_x64.bin
```

Then use the generated beacon as your new shellcode.

## Profiles  

To use profiles in Cobalt Strike, execute the following command:  
```bash
bash teamserver <your_ip> <your_password> <path/to/your.profile>
```

## References  
https://www.elastic.co/blog/detecting-cobalt-strike-with-memory-signatures  
https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_CobaltStrike.yar  
https://github.com/xx0hcd/Malleable-C2-Profiles/blob/master/normal/amazon_event  

## Author  
Kleiton Kurti ([@kleiton0x00](https://github.com/kleiton0x00))
