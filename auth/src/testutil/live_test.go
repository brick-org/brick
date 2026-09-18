package testutil

// Opt-in live smoke only. Skipped unless BRICK_AUTH_LIVE_SMOKE=1, so normal
// CI (and `go test ./...`) never touches the network. When enabled it
// performs best-effort HEAD requests against the documented provider
// authorize endpoints and fails on transport errors or 5xx responses.

import (
	"net/http"
	"os"
	"testing"
	"time"
)

func TestLiveSmoke_OptIn(t *testing.T) {
	if os.Getenv("BRICK_AUTH_LIVE_SMOKE") != "1" {
		t.Skip("live smoke is opt-in only (BRICK_AUTH_LIVE_SMOKE=1)")
	}
	client := &http.Client{Timeout: 10 * time.Second}
	for _, endpoint := range []string{
		"https://id.kick.com/oauth/authorize",
		"https://accounts.google.com/o/oauth2/v2/auth",
		"https://appleid.apple.com/auth/authorize",
		"https://auth.atlassian.com/authorize",
		"https://dash.cloudflare.com/oauth2/auth",
		"https://discord.com/api/oauth2/authorize",
		"https://www.dropbox.com/oauth2/authorize",
		"https://www.facebook.com/v24.0/dialog/oauth",
		"https://www.figma.com/oauth",
		"https://github.com/login/oauth/authorize",
		"https://gitlab.com/oauth/authorize",
		"https://huggingface.co/oauth/authorize",
		"https://kauth.kakao.com/oauth/authorize",
		"https://access.line.me/oauth2/v2.1/authorize",
		"https://linear.app/oauth/authorize",
		"https://www.linkedin.com/oauth/v2/authorization",
		"https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
		"https://nid.naver.com/oauth2.0/authorize",
		"https://api.notion.com/v1/oauth/authorize",
		"https://polar.sh/oauth2/authorize",
		"https://backboard.railway.com/oauth/auth",
		"https://www.reddit.com/api/v1/authorize",
		"https://apis.roblox.com/oauth/v1/authorize",
		"https://login.salesforce.com/services/oauth2/authorize",
		"https://slack.com/openid/connect/authorize",
		"https://accounts.spotify.com/authorize",
		"https://www.tiktok.com/v2/auth/authorize",
		"https://id.twitch.tv/oauth2/authorize",
		"https://x.com/i/oauth2/authorize",
		"https://vercel.com/oauth/authorize",
		"https://id.vk.com/authorize",
		"https://open.weixin.qq.com/connect/qrconnect",
		"https://zoom.us/oauth/authorize",
	} {
		req, err := http.NewRequest(http.MethodHead, endpoint, nil)
		if err != nil {
			t.Fatalf("HEAD %s: %v", endpoint, err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("HEAD %s: %v", endpoint, err)
		}
		_ = resp.Body.Close()
		t.Logf("HEAD %s -> %d", endpoint, resp.StatusCode)
		if resp.StatusCode >= 500 {
			t.Errorf("HEAD %s -> %d, want < 500", endpoint, resp.StatusCode)
		}
	}
}
