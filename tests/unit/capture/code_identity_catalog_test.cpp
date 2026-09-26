#include "capture/code_identity_catalog.hpp"
#include <iostream>

int main() {
    janus::CodeIdentityCatalog catalog;
    const auto first = catalog.Intern(0x1000, 1, 2, {0x90, 0x90});
    const auto same = catalog.Intern(0x1000, 1, 2, {0x90, 0x90});
    const auto modified = catalog.Intern(0x1000, 1, 2, {0x90, 0xcc});
    const auto reloaded = catalog.Intern(0x1000, 2, 2, {0x90, 0xcc});
    const auto elsewhere = catalog.Intern(0x2000, 2, 2, {0x90, 0xcc});
    if ( !first.created || first.instructionId != 1 )
        return 1;
    if ( same.created || same.instructionId != first.instructionId )
        return 2;
    if ( !modified.created || modified.instructionId == first.instructionId )
        return 3;
    if ( !reloaded.created || reloaded.instructionId == modified.instructionId )
        return 4;
    if ( !elsewhere.created ||
         elsewhere.instructionId == reloaded.instructionId )
        return 5;

    if ( modified.instructionId != 2 || reloaded.instructionId != 3 ||
         elsewhere.instructionId != 4 ) {
        std::cerr << "instruction ids are not deterministic\n";
        return 6;
    }

    return 0;
}
