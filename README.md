This curated list of reverse engineering resources started as awesome-reversing forked from @tylerha97. I have updated some of the resources and will continue to curate into the future. Thanks, for visiting.

- Contents:
    - [Introduction](#introduction)
    - [Creating a safe environment](#environment)
    - [Characterizing the software](#characteristics)
    - [Static analysis](#static-analysis)
    - [Dynamic analysis](#dynamic-analysis)
    - [Practice, practice, practice](#practice)
    - [Additional resources](#resources)
- - -
## Introduction
*Welcome to reverse engineering!*

* [Learn Assembly](https://github.com/ZakiRucker/h4cker/blob/master/buffer_overflow_example/learn_assembly.md) - Learing assembly will be necessary to become proficient. This is a great primer to set you up for further study.
* [Assembly Language Step-by-Step](https://www.wiley.com/en-us/Assembly+Language+Step+by+Step%3A+Programming+with+Linux%2C+3rd+Edition+-p-9781118080993) - An excellent starting point point to learn Intel based 32 bit architecture x86 assembly language. Wiley has released the [4th edition](https://www.wiley.com/en-us/x64+Assembly+Language+Step+by+Step%3A+Programming+with+Linux%2C+4th+Edition-p-9781394155255) based on x64 architecture. 
* [Reverse Engineering for Beginners](http://beginners.re/)
* [Introducing the Arm architecture](https://developer.arm.com/documentation/102404/0201/About-the-Arm-architecture?lang=en)
* [Apple Silicon Developer Documentation](https://developer.apple.com/documentation/apple-silicon)
* [Intel® 64 and IA-32 Architectures Software Developer Manuals](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html) - The go to reference for Intel architecture based assembly
* [Learn The Architecture - A64 instruction set architecture](https://github.com/ZakiRucker/Reverse-Engineering/files/12404652/learn_the_architecture_-_a64_instruction_set_architecture_102374_0101_02_en.pdf)

## Environment
*Creating a safe space to hone your skills*

Not every file is safe to run in your environment take steps to ensure your machine and network are protected.
* [Proxmox](https://www.proxmox.com/en/proxmox-virtual-environment/overview)
* [VirtualBox](https://www.virtualbox.org)
* [VMware](https://www.vmware.com/products/workstation-pro.html)
* [Cuckoo Sandbox](https://cuckoosandbox.org)

## Characteristics
*What is this thing?*

Become accustomed to trying to determine something about the file before you run it.
* [md5](https://www.commandlinux.com/man-page/man3/md5.3bsd.html)
* [shasum](https://www.commandlinux.com/man-page/man1/shasum.1.html)
* [file](https://www.commandlinux.com/man-page/man1/file.1.html)

## Static Analysis
*Peeking in the medicine cabinet*

Be cautious to learn as much as you can before running an unknown executable on your machine.
* [HxD](https://mh-nexus.de/en/hxd/)
* [010 Editor](http://www.sweetscape.com/010editor/)
* [Hex Workshop](http://www.hexworkshop.com/)
* [HexFiend](http://ridiculousfish.com/hexfiend/)
* [Hiew](http://www.hiew.ru/)
* [ImHex](https://github.com/WerWolv/ImHex)
* [CFF Explorer](http://www.ntcore.com/exsuite.php)
* [Cerbero Profiler](http://cerbero.io/profiler/)
* [Detect It Easy](https://horsicq.github.io)
* [PeStudio](http://www.winitor.com/)
* [PEiD](https://www.aldeid.com/wiki/PEiD)
* [PPEE](https://www.mzrst.com/)
* [Android Developer Studio](http://developer.android.com/sdk/index.html)
* [APKtool](https://github.com/iBotPeaches/Apktool)
* [dex2jar](https://github.com/pxb1988/dex2jar)
* [yarGen](https://github.com/Neo23x0/yarGen)
* [yabin](https://github.com/AlienVault-OTX/yabin)
* [ollvm](https://github.com/obfuscator-llvm/obfuscator)
* [movfuscator](https://github.com/Battelle/movfuscator)
* [Tigress](http://tigress.cs.arizona.edu/)
* [AD_1DA (metamorphism)](https://github.com/n4sm/AD_1DA)
* [MachoView](https://github.com/gdbinit/MachOView)
* [AppEncryptor](https://github.com/AlanQuatermain/appencryptor) - Tool for decrypting
* [Class-Dump](http://stevenygard.com/projects/class-dump/) - use deprotect option 
* [readmem](https://github.com/gdbinit/readmem) - OS X Reverser's process dumping tool

## Dynamic Analysis
*Poking the bear*

* [Ghidra](https://ghidra-sre.org/)
* [IDA Pro](https://www.hex-rays.com/products/ida/index.shtml)
* [Binary Ninja](https://binary.ninja/)
* [JEB](https://www.pnfsoftware.com/jeb2/)
* [Radare](http://www.radare.org/r/)
* [Hopper](http://hopperapp.com/)
* [Capstone](http://www.capstone-engine.org/)
* [objdump](http://linux.die.net/man/1/objdump)
* [fREedom](https://github.com/cseagle/fREedom)
* [Retdec](https://retdec.com/)
* [dnSpy](https://github.com/0xd4d/dnSpy)
* [Bytecode Viewer](https://bytecodeviewer.com/)
* [JPEXS Flash Decompiler](https://www.free-decompiler.com/flash/)
* [Snowman](https://tracxn.com/d/companies/snowman/__UT5m_dFEv0s1uPjSJD-shuyUAbb4EjGjA0kl-xgiIrE)
* [dotPeek](https://www.jetbrains.com/decompiler/)
* [Mobius Resources](http://www.msreverseengineering.com/research/)
* [bap](https://github.com/BinaryAnalysisPlatform/bap)
* [angr](https://github.com/angr/angr)
* [Scylla](https://github.com/NtQuery/Scylla)
* [ProcessHacker](http://processhacker.sourceforge.net/)
* [Process Explorer](https://technet.microsoft.com/en-us/sysinternals/processexplorer)
* [Process Monitor](https://technet.microsoft.com/en-us/sysinternals/processmonitor)
* [Autoruns](https://technet.microsoft.com/en-us/sysinternals/bb963902)
* [Noriben](https://github.com/Rurik/Noriben)
* [API Monitor](http://www.rohitab.com/apimonitor)
* [iNetSim](http://www.inetsim.org/)
* [Wireshark](https://www.wireshark.org/download.html)
* [netzob](https://www.netzob.org/)
* [Volatility](https://github.com/volatilityfoundation/volatility)
* [Dumpit](https://eyehatemalwares.com/digital-forensics/memory-acquisition/dumpit/)
* [LiME](https://github.com/504ensicsLabs/LiME)
* [Cuckoo](https://www.cuckoosandbox.org/)
* [Objective-See Utilities](https://objective-see.com/products.html)
* [dtrace](http://dtrace.org/blogs/brendan/2011/10/10/top-10-dtrace-scripts-for-mac-os-x/) - sudo dtruss = strace [dtrace recipes](http://mfukar.github.io/2014/03/19/dtrace.html)
* [Frida](https://frida.re/)
* [BluePill](https://github.com/season-lab/bluepill) - Analysis and debugging of evasive malware and protected executables
* [Dexcalibur](https://github.com/FrenchYeti/dexcalibur)
* [GDB step by step introduction](https://www.geeksforgeeks.org/gdb-step-by-step-introduction/) - A solid intro to the GNU De Bugger tool aimed at total beginners.
* [WinDbg](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-download-tools)
* [x64dbg](http://x64dbg.com/#start)
* [gdb](https://www.gnu.org/software/gdb/)
* [vdb](https://github.com/vivisect/vivisect)
* [lldb](http://lldb.llvm.org/)
* [qira](http://qira.me/)
* [Ole Tools](http://www.decalage.info/python/oletools)
* [Didier's PDF Tools](http://blog.didierstevens.com/programs/pdf-tools/)
* [Origami](https://github.com/cogent/origami-pdf)
* [unicorn](https://github.com/unicorn-engine/unicorn)
* [Jadx](https://github.com/skylot/jadx)
* [Smali](https://github.com/JesusFreke/smali)
* [Triton](https://triton.quarkslab.com/)
* [The IDA Pro Book](https://nostarch.com/idapro2.htm)
* [The Ghidra Book](https://nostarch.com/GhidraBook)
* [The Beginner's Guide to IDA Python](https://leanpub.com/IDAPython-Book)
* [Assembly Language for Intel-Based Computers (5th Edition) ](https://www.goodreads.com/book/show/7646341-assembly-language-for-intel-based-computers)
* [Hacker Disassembly Uncovered](https://www.goodreads.com/book/show/435687.Hacker_Disassembling_Uncovered?ac=1&from_search=true&qid=HUNC0IiiY0&rank=1)
* [BugProve](https://bugprove.com) Jaw dropping tool to highlight vulnerabilities in binaries. I dare you to upload your router firmware.
    
## Practice
*Do or do not, there is no try*

* [Dr. Fu's Malware Analysis Tutorials](http://fumalwareanalysis.blogspot.sg/p/malware-analysis-tutorials-reverse.html)
* [Lena's Reversing for Newbies](https://forum.tuts4you.com/files/file/1307-lenas-reversing-for-newbies/)
* [Open Security Training](http://opensecuritytraining.info/Training.html)
* [Binary Auditing Training](https://github.com/Info-security/binary-auditing-training)
* [Practical Malware Analysis](https://github.com/mikesiko/PracticalMalwareAnalysis-Labs)
* [Modern Binary Exploitation](https://web.archive.org/web/20210710080726/http://security.cs.rpi.edu/courses/binexp-spring2015/)
* [RPISEC Malware Analysis Course](https://github.com/RPISEC/Malware)
* [Reverse Engineering for Beginners](https://www.begin.re/)
* [RE101](https://github.com/zigzig122468/securedorg.github.io/blob/master/RE101.md)
* [RE102](https://github.com/Rurik/securedorg.github.io/tree/master/RE102)
* [ARM Assembly Basics](https://training.azeria-labs.com/arm-courses.html)
* [Binary Auditing Course](https://github.com/Info-security/binary-auditing-training)

#### Level-up
*Teach a student to fish*

* [Crackmes.one](http://www.crackmes.one/) - Binaries of different types and difficulties to practice, along with excellent write-ups.
* [OSX Crackmes](https://reverse.put.as/crackmes/)
* [Github CTF Archives](http://github.com/ctfs/)
* [Reverse Engineering Challenges](http://challenges.re/)
* [xorpd Advanced Assembly Exercises](http://www.xorpd.net/pages/xchg_rax/snip_00.html)
* [Virusshare.com](http://virusshare.com/)
* [Contagio](http://contagiodump.blogspot.com/)
* [Malware-Traffic-Analysis](https://www.malware-traffic-analysis.net)
* [Malshare](http://malshare.com/)
* [malwr.com](https://malwr.co/)
* [vxvault](http://vxvault.net/)
* [Root Me Challenges](https://www.root-me.org/en/Challenges/Cracking)
* [theZoo](https://github.com/ytisf/theZoo)
* [IDA Python Src](https://github.com/idapython/src)
* [IDC Functions Doc](https://www.hex-rays.com/products/ida/support/idadoc/162.shtml)
* [Using IDAPython to Make your Life Easier](http://researchcenter.paloaltonetworks.com/tag/idapython/)
* [IDA Plugin Contest](https://www.hex-rays.com/contests/)
* [onehawt IDA Plugin List](https://github.com/onethawt/idaplugins-list)
* [pefile Python Libray](https://github.com/erocarrera/pefile)
* [ghidra ninja](https://github.com/ghidraninja/ghidra_scripts)
* [USB reversing](https://github.com/openrazer/openrazer/wiki/Reverse-Engineering-USB-Protocol)


#### Next level
*Better practice means better gains*

* Write your own programs in C or C++ then reverse engineer them. This practice has the added effect of making you a better programmer.
* [Compiler Explorer](https://godbolt.org) - This nifty tool lets you write out some code in a variety of higher level languages and see them in various compilers in a side-by-side view.
* [Decompiler Explorer](https://dogbolt.org) - This gem lets you upload a binary and view it side-by-side in multiple decompilers to compare the results.

#### Are you up for a greater challenge?
*Take your experience to the next level*

* Use a tool from a company like 1BitSquared and pull the firmware off of an embedded device and reverse engineer that.
* [1BitSquared](https://1bitsquared.com) - Tools to read JTAGs and interface with embedded devices.

## Resources
*Where to go for more information*

* [Practical Reverse Engineering](https://www.wiley.com/en-us/Practical+Reverse+Engineering:+x86,+x64,+ARM,+Windows+Kernel,+Reversing+Tools,+and+Obfuscation-p-9781118787311)
* [Reversing: Secrets of Reverse Engineering](https://www.wiley.com/en-us/Reversing%3A+Secrets+of+Reverse+Engineering+-p-9780764574818)
* [Gray Hat Hacking](https://www.accessengineeringlibrary.com/content/book/9781264268948)
* [The Art of Memory Forensics](https://www.wiley.com/en-us/The+Art+of+Memory+Forensics:+Detecting+Malware+and+Threats+in+Windows,+Linux,+and+Mac+Memory-p-9781118825099)
* [Hacking: The Art of Exploitation](https://nostarch.com/hacking2.htm) - This book has a section on assembly language which I found extremely helpful to understand the basics.
* [Fuzzing for Software Security](https://us.artechhouse.com/Fuzzing-for-Software-Security-Testing-and-Quality-Assurance-Second-Edition-P1930.aspx)
* [Art of Software Security Assessment](http://amzn.com/0321444426)
* [The Antivirus Hacker's Handbook](https://www.wiley.com/en-us/The+Antivirus+Hacker%27s+Handbook-p-9781119028789)
* [The Rootkit Arsenal](https://www.jblearning.com/catalog/productdetails/9781449626365)
* [The Shellcoders Handbook](https://www.wiley.com/en-us/The+Shellcoder%27s+Handbook%3A+Discovering+and+Exploiting+Security+Holes%2C+2nd+Edition-p-9780470080238)
* [A Guide to Kernel Exploitation](https://shop.elsevier.com/books/a-guide-to-kernel-exploitation/perla/978-1-59749-486-1)
* [Yara docs](http://yara.readthedocs.org/en/v3.4.0/writingrules.html)
* [Agner's software optimization resources](http://www.agner.org/optimize/)
* [Binary Analysis](https://nostarch.com/binaryanalysis)
* [Rootkits and Bootkits](https://nostarch.com/rootkits)
* [Serious Cryptography](https://nostarch.com/seriouscrypto)
* [Attacking Network Protocols](https://nostarch.com/networkprotocols)
* [radare2book](https://radare.gitbooks.io/radare2book)

##### Windows
* [Windows Internals Part 1](https://www.microsoftpressstore.com/store/windows-internals-part-1-system-architecture-processes-9780735684188) [Part 2](https://www.microsoftpressstore.com/store/windows-internals-part-2-9780135462331)
* [Inside Windows Debugging](https://www.microsoftpressstore.com/store/inside-windows-debugging-9780735662780)

##### Apple
* [iOS Reverse Engineering](https://github.com/iosre/iOSAppReverseEngineering)

##### Malware Analysis
* [Practical Malware Analysis](https://nostarch.com/malware)
* [Malware Analyst's Cookbook](https://www.wiley.com/en-us/Malware+Analyst%27s+Cookbook+and+DVD%3A+Tools+and+Techniques+for+Fighting+Malicious+Code-p-9780470613030)
* [Learning Malware Analysis](https://www.packtpub.com/product/learning-malware-analysis/9781788392501)


### VLOGs worth watching
* [OALabs](https://www.youtube.com/channel/UC--DwaiMV-jtO-6EvmKOnqg)
* [MalwareTechVlog](https://www.youtube.com/channel/UCLDnEn-TxejaDB8qm2AUhHQ)
* [GynvaelEN](https://www.youtube.com/user/GynvaelEN)
* [Virus Bulletin](https://www.youtube.com/user/virusbtn)
* [Intro to WinDBG](https://www.youtube.com/playlist?list=PLhx7-txsG6t6n_E2LgDGqgvJtCHPL7UFu)
* [hasherzade](https://www.youtube.com/channel/UCNWVswPNgn5kutPNa5sprkg)
* [cybercdh](https://www.youtube.com/channel/UCND1KVdVt8A580SjdaS4cZg)
* [MalwareAnalysisForHedgehogs](https://www.youtube.com/channel/UCVFXrUwuWxNlm6UNZtBLJ-A)
