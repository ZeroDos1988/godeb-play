package wireguard

import "testing"

func TestPlayProfileFromHub(t *testing.T) {
	conf := "# GoDeb-Client: spiele\n# GoDeb-Role: site\n# GoDeb-Profile: play\n" + siteClientConf()
	if p := JoinProfile(JoinCode(conf)); p.Kind != ProfilePlay {
		t.Fatalf("profile %+v", p)
	}
	jc, _, err := parseJoinConfig(conf)
	if err != nil {
		t.Fatal(err)
	}
	if DetectRole(renderPeerConfig(jc)).Profile.Kind != ProfilePlay {
		t.Fatal("profile not kept in wg0.conf")
	}
	if JoinProfile(siteClientConf()).Kind != "" {
		t.Fatal("plain site file has a profile")
	}
	for _, bad := range []string{"# GoDeb-Profile: root\n", "# GoDeb-Profile: play\n# GoDeb-Mail-Host: postfach.example.com\n"} {
		if _, _, err := parseJoinConfig(bad + siteClientConf()); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}
