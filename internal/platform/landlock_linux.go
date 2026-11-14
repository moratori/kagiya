package platform

// RestrictWrites は、書き込める場所を dirs の下だけに限る（Landlock）。
func RestrictWrites(dirs []string) (status, note string) { return "unsupported", "not implemented" }
