//after showAd()
var google_bypass = flag.Bool("google-bypass", false, "Enable Google Bypass")

func init() {
	flag.Parse()
	if *google_bypass {
		display := ":99"
		if disp := getenv("DISPLAY", ""); disp != "" {
			display = disp
		}
		exec.Command("pkill", "-f", "google-chrome.*--remote-debugging-port=9222").Run()
		log.Debug("Killed all google-chrome instances on port 9222")
		cmd := exec.Command("google-chrome", "--remote-debugging-port=9222", "--no-sandbox", "--disable-web-security") // Added
		var out, stderr bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &stderr
		cmd.Env = append(cmd.Env, fmt.Sprintf("DISPLAY=%s", display))
		if err := cmd.Start(); err != nil {
			log.Error("Failed to start Chrome: %v, output: %s", err, stderr.String())
			return
		}
		log.Debug("Started Chrome in debug mode on port 9222")
		go func() {
			if err := cmd.Wait(); err != nil {
				log.Error("Chrome exited: %v, output: %s", err, stderr.String())
			}
		}()
		launcher.NewBrowser().MustGet()
	}
}

func getenv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}