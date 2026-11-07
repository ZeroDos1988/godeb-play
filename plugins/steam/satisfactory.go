package steam

// Satisfactory's dedicated server has no settings file to edit: the first
// player who connects claims the server and sets the admin password in the
// game. Ports since 1.0: 7777 UDP and TCP (game and HTTPS API) plus 8888
// TCP. Claim the server before the hub forwards the ports to the internet.

func init() {
	register(&Game{
		ID:         "satisfactory",
		Name:       "Satisfactory",
		AppID:      "1690800",
		Platform:   Linux,
		Executable: "FactoryServer.sh",
		StopSignal: "SIGINT",
		DownloadGB: 8,
		MemoryGB:   12,
		Ports:      func(map[string]any) []int { return []int{7777} },
		TCPPorts:   func(map[string]any) []int { return []int{7777, 8888} },
		// HOME is the base directory; Unreal keeps the saves below it.
		SaveDir: func(map[string]any) string { return ".config/Epic/FactoryGame/Saved/SaveGames" },
	})
}
