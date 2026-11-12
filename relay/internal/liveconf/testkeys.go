// SPDX-License-Identifier: Apache-2.0

package liveconf

import "slices"

// testKeyThumbprints are the JWK thumbprints (RFC 7638, SHA-256) of the Ed25519 and P-256 keys
// of relay/conformance/keys/test-keys.json. The private parts of these keys are public: the
// tool refuses to use any of them with a live operator (RELAY-v0 section 8.2). A test checks
// the list against the file.
var testKeyThumbprints = []string{
	"EFbVv_TBw9U6Jhw-4ZkXNilXk5fC4VHKuLLkoO_wUzA", // relay-installation
	"goLvIcw0RjrP8YU1PBj1SUnqhQTDnkfW2-TjeYwB2kc", // relay-other
	"c1YnZzkw0gupjxd8J8tIZuhbtxqsfprMttcUCP0g2fo", // relay-new
	"2VFUO_WDVSqQ9XI2N6YaQFYZh2J04rTY6GfrHP2OWzE", // relay-p256
	"osKmKxUz13plDQRAE7cOCWslfLQGoMQwvHB-5Fi6rR8", // relay-tunnel
	"XxODViWgwdOrGSDQodJF52ROiq8j2IMJvoSiRKRsLAw", // relay-tunnel-old
	"lgP9ME4-CQefxidsDbcOosSMmtXKcBXryOlPCLg-Wdg", // relay-tunnel-ca
	"c45hybioamW9eIAYn_GTzjer5wRSot7-LtXbAaQFYps", // relay-tunnel-p256
}

// isTestKey reports whether the thumbprint is that of a test key.
func isTestKey(thumbprint string) bool { return slices.Contains(testKeyThumbprints, thumbprint) }
