package dest

import "encoding/base64"

func base64DecodeURL(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }
