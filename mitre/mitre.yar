rule screenshot : T1113 {
    meta:
        description = "Takes screenshot"
    strings:
        $d1 = "libc6.so" nocase
        $d2 = "libdl.so.2" nocase
        $c1 = "libutil.so.1"
        $c2 = "opencv.so"
    condition:
        1 of ($d*) and 1 of ($c*)
}


rule inject_remote_thread : T1055 {
    meta:
        description = "Code injection"
    strings:
        $c1 = "bash"
        $c2 = "python"
        $c3 = "dlopen"
        $c4 = "perl"
        $c5 = "dlsym"
    condition:
        $c1 and $c2 and ( $c3 or $c4 ) and ( $c5 )
}

rule  cmd : T1059
{
    meta:
        description = "Command line"
    strings:
        $a0 = "bash" nocase wide ascii
        $a1 = "rbash" nocase wide ascii
        $a2 = "sh" nocase wide ascii
        $a3 = "zsh" nocase wide ascii

    condition:
        any of them
}


rule  application_windows_discovery : T1010
{
    meta:
        description = "Enumerate windows and child window"
    strings:
        $s0 = "wmctrl"
        $s1 = "xwininfo"
        $s2 = "xlsclients"
        $s3 = "_NET_CLIENT_LIST_STACKING"

    condition:
        ( $s1 and $s2 ) or $s0 or $s3
}

rule  input_capture : T1056
{
    meta:
        description = "Capturing user input to obtain credentials or collect information"
    strings:
        $s0 = "dlopen"
        $s1 = "dlclose"
    condition:
        $s0 or $s1
}


rule  Base64d_PE : T1027
{
	meta:
		description = "Contains a base64-encoded executable"
		author = "Florian Roth"
		date = "2017-04-21"

	strings:
		$s0 = "TVqQAAIAAAAEAA8A//8AALgAAAA" wide ascii
		$s1 = "TVqQAAMAAAAEAAAA//8AALgAAAA" wide ascii

	condition:
		any of them
}

rule  RijnDael_AES : T1573
{	meta:
		author = "_pusher_"
		description = "RijnDael AES"
		date = "2016-06"
	strings:
		$c0 = { A5 63 63 C6 84 7C 7C F8 }
	condition:
		$c0
}