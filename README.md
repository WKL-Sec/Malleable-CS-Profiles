# Malleable-CS-Profiles
A list of python tools to help create an OPSEC-safe Cobalt Strike profile. This is the Github repository of the [Part 1](https://whiteknightlabs.com/2023/05/23/unleashing-the-unseen-harnessing-the-power-of-cobalt-strike-profiles-for-edr-evasion/) and [Part 2](https://whiteknightlabs.com/2025/05/08/harnessing-the-power-of-cobalt-strike-profiles-for-edr-evasion/) blogpost.  

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

### dll_parse.py  
A python script parses the given DLL, in order to generate a ready-to-use Cobalt Strike profile block. This will make the reflected DLL looks like a system DLL. 
```bash
python3 dll_parse.py <path/to/dll>
```

### magic_mz.py  
A python script which dynamically generates (OPSEC-safe) values for `magic_mz_x64` and `magic_mz_x86` MZ PE header which are not obfuscated as the reflective loading process depends on them. When executed, the script provides a set of 2 (for x64) or 4 (for x86) assembly instructions. The condition for the assembly instructions is that the resultant should be a no operation.

```bash
python3 magic_mz
```

### rich_header.py (deprecated)  
⚠️ Deprecated: A python script which generates dynamic shellcode that is responsible for the meta-information inserted by the compiler. The Rich header is a PE section that serves as a fingerprint of a Windows' executable’s build environment. To use the script, execute:  
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

### rule_f0b627fc_bypass.py (deprecated)  
⚠️ Deprecated: A python script which modifies the shellcode in order bypass rule `Windows_Trojan_CobaltStrike_f0b627fc` from Elastic. To use the script, execute:  
```bash
python3 rule_f0b627fc_bypass.py  beacon_x64.bin
```

Then use the generated beacon as your new shellcode.

## Profiles  

We are providing three different profile templates under the `Profiles` folder. Each template includes two profiles, one with and without `post-ex` strings. To use profiles in Cobalt Strike, start the teamserver with the following command:  
```bash
bash teamserver <your_ip> <your_password> <path/to/your.profile>
```

## References  
https://www.elastic.co/blog/detecting-cobalt-strike-with-memory-signatures  
https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_CobaltStrike.yar  
https://github.com/xx0hcd/Malleable-C2-Profiles/blob/master/normal/amazon_event  

## Author  
Kleiton Kurti ([@kleiton0x00](https://github.com/kleiton0x00))
