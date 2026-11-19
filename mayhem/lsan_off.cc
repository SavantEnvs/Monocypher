// Leak detection is not the bug class this integration fuzzes for (SPEC §6.2 item 15);
// ASan's memory-safety checks and UBSan stay fully on.
extern "C" int __lsan_is_turned_off() { return 1; }
