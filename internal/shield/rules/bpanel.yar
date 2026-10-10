import "math"

/*
 * BPANEL Shield built-in YARA rules (same ideas as heuristic.go).
 * meta.verdict is "infected" or "suspicious"; meta.severity low..critical.
 */

rule BPANEL_EICAR_Test
{
    meta:
        verdict = "infected"
        severity = "critical"
        description = "EICAR antivirus test string"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule BPANEL_PHP_Eval_Decode
{
    meta:
        verdict = "infected"
        severity = "high"
        description = "eval/assert of a decoded payload"
    strings:
        $a = /(eval|assert)\s*\(\s*@?\s*(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|convert_uudecode|hex2bin)\s*\(/ nocase
    condition:
        $a
}

rule BPANEL_PHP_Decode_Chain
{
    meta:
        verdict = "suspicious"
        severity = "medium"
        description = "nested decoder chain"
    strings:
        $a = /(gzinflate|gzuncompress|gzdecode|str_rot13|strrev)\s*\(\s*(base64_decode|str_rot13|gzinflate|strrev)\s*\(/ nocase
    condition:
        $a
}

rule BPANEL_PHP_Preg_Replace_E
{
    meta:
        verdict = "infected"
        severity = "high"
        description = "preg_replace with the /e modifier"
    strings:
        $a = /preg_replace\s*\(\s*['"]\/[^\/'"]*\/[a-z]*e[a-z]*['"]\s*,/ nocase
    condition:
        $a
}

rule BPANEL_PHP_Input_Exec
{
    meta:
        verdict = "infected"
        severity = "critical"
        description = "request input passed to command execution or assert"
    strings:
        $a = /(system|exec|passthru|shell_exec|popen|proc_open|pcntl_exec|assert)\s*\([^;]{0,60}\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $b = /\$_(GET|POST|REQUEST|COOKIE)\s*\[[^\]]{1,40}\]\s*\(/
    condition:
        any of them
}

rule BPANEL_Webshell_Markers
{
    meta:
        verdict = "infected"
        severity = "critical"
        description = "known web shell markers (c99, r57, WSO, b374k, FilesMan)"
    strings:
        $c99a = "c99shell" nocase
        $c99b = "c99_buff_prepare"
        $r57a = "r57shell" nocase
        $r57b = "r57_pwd"
        $wso = "wso_version"
        $b374k = "b374k" nocase
        $fm = "FilesMan"
    condition:
        any of them
}

rule BPANEL_PHP_In_Image
{
    meta:
        verdict = "infected"
        severity = "high"
        description = "PHP open tag inside a PNG/JPEG/GIF"
    strings:
        $php = "<?php" nocase
        $short = "<?="
    condition:
        (uint32be(0) == 0x89504E47 or uint16be(0) == 0xFFD8 or uint32be(0) == 0x47494638) and any of them
}

rule BPANEL_PHP_Chr_Concat
{
    meta:
        verdict = "suspicious"
        severity = "medium"
        description = "chr() concatenation obfuscation"
    strings:
        $a = /(chr\s*\(\s*[0-9]{1,3}\s*\)\s*\.\s*){8}/ nocase
    condition:
        $a
}

rule BPANEL_Long_Base64_In_PHP
{
    meta:
        verdict = "suspicious"
        severity = "medium"
        description = "long base64 blob inside a PHP file"
    strings:
        $php = "<?php" nocase
        $b64 = /[A-Za-z0-9+\/]{1024}/
    condition:
        $php and $b64 and math.entropy(@b64[1], !b64[1]) >= 5.0
}
