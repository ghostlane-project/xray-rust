/* Stands in for the iOS app: links libolc_spike_ios_link.a the way an Xcode target links a
 * Rust static library, and runs the same checks as the Rust binary. */
int olc_spike_ios_run(void);

int main(void) { return olc_spike_ios_run(); }
