#include "bcontrol/diagnostic_assets.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
static char *redact(const char *source) {
    uint32_t length = 0;
    assert(bc_diagnostic_jnlp_redact((const uint8_t *)source, (uint32_t)strlen(source), NULL, 0, &length) == BC_OK && length);
    char *out = malloc((size_t)length + 1); assert(out);
    uint32_t written = 0;
    assert(bc_diagnostic_jnlp_redact((const uint8_t *)source, (uint32_t)strlen(source), out, length + 1, &written) == BC_OK && written == length && out[written] == 0);
    return out;
}
int main(void) {
    const char *source = "<?xml version='1.0'?><jnlp codebase='https://user:secret-url@bmc/Java?cookie=secret-query' href='viewer.jnlp?session=secret-session'>"
        "<!--secret-comment--><information><title>secret-title</title></information><resources>"
        "<jar href='release/client.jar' main='true' version='secret-version'/><jar href='https://bmc/client.jar?password=secret-archive'/>"
        "<nativelib href='native.jar?token=secret-native'/></resources>"
        "<application-desc main-class='com.ami.kvm.jviewer.JViewer'>"
        "<argument>-hostname</argument><argument>secret-host</argument><argument>-kvmtoken</argument><argument>secret-ticket</argument>"
        "<argument>-webcookie</argument><argument>secret-cookie</argument><argument>-kvmport</argument><argument>7&#53;82</argument>"
        "<argument>-kvmsecure</argument><argument>1</argument><argument>-singleportenabled</argument><argument>0</argument>"
        "<argument>-unknownName</argument><argument>secret-unknown</argument><argument>-clientrand</argument><argument>secret-random</argument>"
        "<argument>-password</argument><argument>secret-password</argument><argument>-csrf</argument><argument>secret-csrf</argument>"
        "</application-desc></jnlp>";
    char *out = redact(source);
    assert(!strstr(out, "secret-") && !strstr(out, "https://") && !strstr(out, "?cookie") && !strstr(out, "?session"));
    assert(strstr(out, "href=\"release/client.jar\"") && strstr(out, "main=\"true\""));
    assert(strstr(out, "com.ami.kvm.jviewer.JViewer") && strstr(out, "<argument>-unknownName</argument>"));
    assert(strstr(out, "<argument>-kvmport</argument><argument>7582</argument>"));
    assert(strstr(out, "<argument>-kvmsecure</argument><argument>1</argument>"));
    uint32_t size = 0;
    assert(bc_diagnostic_jnlp_redact((const uint8_t *)out, (uint32_t)strlen(out), NULL, 0, &size) == BC_OK);
    free(out);
    out = redact("<jnlp><applet-desc archive='lib/viewer.jar,lib/support.jar'>"
        "<param value='secret-verify' name='verifyValue'/><param name='decrykey' value='secret-key'/>"
        "<param name='verifyValueExt' value='secret-ext'/><param name='CSRF' value='secret-csrf'/>"
        "<param name='session' value='secret-session'/><param name='ClientRandom' value='12345678'/>"
        "<param name='port' value='5900'/><param name='vmmPort' value='623'/><param name='compress' value='1'/>"
        "<param name='port' value='65536'/><param name='secure' value='secret-bool'/>"
        "<param name='unknown' archive='secret-not-resource.jar' value='secret-other'/>"
        "</applet-desc></jnlp>");
    assert(!strstr(out, "secret-") && !strstr(out, "12345678") && !strstr(out, "65536"));
    assert(strstr(out, "archive=\"lib/viewer.jar,lib/support.jar\"") && strstr(out, "name=\"port\" value=\"5900\""));
    assert(strstr(out, "name=\"vmmPort\" value=\"623\"") && strstr(out, "name=\"compress\" value=\"1\"")); free(out);
    out = redact("<jnlp><application-desc main-class='vendor.Unknown'><argument>secret-position-user</argument>"
        "<argument>-secret-position-password</argument><argument>623</argument></application-desc>"
        "<resources><jar href='../secret-parent.jar'/><jar href='/secret-root.jar'/><jar href='lib/%73ecret-encoded.jar'/></resources></jnlp>");
    assert(!strstr(out, "secret-") && !strstr(out, ">623<")); free(out);
    out = redact("<?private secret-pi?><jnlp><!--secret-comment--><information>"
        "<title><![CDATA[secret-cdata <&>]]></title></information><applet-desc>"
        "<param name='p&amp;&quot;&apos;&lt;&gt;' value='secret-entity'/><param name='port' value='&#53;900'/>"
        "</applet-desc></jnlp>");
    assert(!strstr(out,"secret-") && !strstr(out,"private") && !strstr(out,"CDATA"));
    assert(strstr(out,"name=\"[redacted]\"") && strstr(out,"value=\"5900\""));
    size = 0;
    assert(bc_diagnostic_jnlp_redact((const uint8_t *)out,(uint32_t)strlen(out),NULL,0,&size) == BC_OK);
    free(out);
    const char *bad[] = {"<jnlp>", "<other/>", "<jnlp token='secret' token='other'/>", "<jnlp>&unknown;</jnlp>",
        "<!DOCTYPE jnlp [<!ENTITY token 'secret-entity'>]><jnlp>&token;</jnlp>"};
    for (unsigned i = 0; i < sizeof(bad)/sizeof(*bad); ++i) {
        char buffer[256]; memset(buffer, 'X', sizeof(buffer)); size = 99;
        assert(bc_diagnostic_jnlp_redact((const uint8_t *)bad[i], (uint32_t)strlen(bad[i]), buffer, sizeof(buffer), &size) != BC_OK);
        assert(!buffer[0] && !size);
    }
    char small[8]; memset(small, 'X', sizeof(small)); size = 0;
    assert(bc_diagnostic_jnlp_redact((const uint8_t *)source, (uint32_t)strlen(source), small, sizeof(small), &size) == BC_LIMIT_EXCEEDED && !small[0] && size > sizeof(small));
    assert(bc_diagnostic_jnlp_redact((const uint8_t *)source, 65537, NULL, 0, &size) == BC_LIMIT_EXCEEDED && !size);
    return 0;
}
