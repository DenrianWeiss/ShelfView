#include "bcontrol/remote_media.h"
#include <assert.h>
#include <string.h>
static bc_string text(const char *value) { return (bc_string){value, strlen(value)}; }
int main(void) {
    bc_remote_media_registry *registry = NULL;
    assert(bc_remote_media_registry_create(2, &registry) == BC_OK);
    bc_string uri = {0};
    assert(bc_remote_media_registry_begin(registry, text("owner"), text("first"), text("/slot")) == BC_OK);
    assert(bc_remote_media_registry_bind(registry, text("owner"), text("second"), &uri) == BC_BUSY);
    assert(bc_remote_media_registry_begin(registry, text("other"), text("other-connection"), text("/slot")) == BC_BUSY);
    bc_remote_media_registry_release(registry, text("first"));
    assert(bc_remote_media_registry_can_mount(registry, text("/slot")) == BC_BUSY);
    assert(bc_remote_media_registry_bind(registry, text("owner"), text("second"), &uri) == BC_OK);
    assert(uri.length == 5 && !memcmp(uri.data, "/slot", 5));
    bc_remote_media_registry_clear(registry, text("first"));
    assert(bc_remote_media_registry_can_mount(registry, text("/slot")) == BC_BUSY);
    assert(bc_remote_media_registry_begin(registry, text("other"), text("third"), text("/other")) == BC_OK);
    assert(bc_remote_media_registry_bind(registry, text("owner"), text("third"), &uri) == BC_BUSY);
    assert(bc_remote_media_registry_begin(registry, text("full"), text("fourth"), text("/full")) == BC_LIMIT_EXCEEDED);
    bc_remote_media_registry_clear(registry, text("second"));
    assert(bc_remote_media_registry_can_mount(registry, text("/slot")) == BC_OK);
    assert(bc_remote_media_registry_bind(registry, text("owner"), text("second"), &uri) == BC_UNSUPPORTED);
    assert(bc_remote_media_registry_begin(registry, text("other"), text("fourth"), text("/another")) == BC_OK);
    bc_remote_media_registry_release(registry, text("fourth"));
    assert(bc_remote_media_registry_bind(registry, text("other"), text("fifth"), &uri) == BC_OK);
    assert(uri.length == 8 && !memcmp(uri.data, "/another", 8));
    assert(bc_remote_media_registry_claim_eject(registry, text("borrower"), text("manual"), text("/other")) == BC_BUSY);
    bc_remote_media_registry_release(registry, text("third"));
    assert(bc_remote_media_registry_claim_eject(registry, text("borrower"), text("manual"), text("/other")) == BC_OK);
    bc_remote_media_registry_release(registry, text("manual"));
    assert(bc_remote_media_registry_bind(registry, text("other"), text("restored"), &uri) == BC_OK);
    assert(uri.length == 6 && !memcmp(uri.data, "/other", 6));
    bc_remote_media_registry_destroy(registry);
    return 0;
}
